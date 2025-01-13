using DotNetNuke.Authentication.SAML.Extensions;
using DotNetNuke.Common;
using DotNetNuke.Common.Lists;
using DotNetNuke.Common.Utilities;
using DotNetNuke.Data;
using DotNetNuke.Entities.Host;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Entities.Profile;
using DotNetNuke.Entities.Users;        
using DotNetNuke.Instrumentation;
using DotNetNuke.Security;
using DotNetNuke.Security.Membership;   
using DotNetNuke.Security.Roles;
using DotNetNuke.Services.Authentication;
using DotNetNuke.Services.Localization;
using DotNetNuke.Services.Log.EventLog;
using DotNetNuke.Services.UserRequest;
using DotNetNuke.UI.Skins.Controls;
using DotNetNuke.UI.UserControls;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Web;
using System.Web.Security;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Security.Cryptography;

namespace DotNetNuke.Authentication.SAML
{
    public partial class Login : AuthenticationLoginBase
    {
		private static readonly ILog Logger = LoggerSource.Instance.GetLogger(typeof (Login));

        private void LogAdminAlertToEventLog(string methodName, string message)
        {
            LogInfo objEventLogInfo = new LogInfo()
            {
                BypassBuffering = true,
                LogTypeKey = "ADMIN_ALERT",
                LogPortalID = PortalSettings.PortalId
            };
            objEventLogInfo.LogProperties.Add(new LogDetailInfo("methodName: ", methodName));
            objEventLogInfo.LogProperties.Add(new LogDetailInfo("Message: ", message));
            ExceptionLogController.Instance.AddLog(objEventLogInfo);
        }

        public override bool Enabled
		{
			get
			{
                return SAMLAuthenticationConfig.GetConfig(PortalId).Enabled;
			}
		}

		protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            if (Request.QueryString["legacy"] != null || Request.IsAuthenticated)
            {
                return;
            }

            string correlationId = Guid.NewGuid().ToString();
            try
            {
                string redirectTo = "~/";

                if (Request.HttpMethod == "POST")
                {
                    this.AuthenticationType = "SAML";
                    SAMLAuthenticationConfig config = SAMLAuthenticationConfig.GetConfig(PortalId);                    
                    //specify the certificate that your SAML provider has given to you
                    string samlCertificate = config.TheirCert;

                    Saml.Response samlResponse = new Saml.Response(samlCertificate);
                    Logger.Debug($"CorrelationId={correlationId}. Request.Form[SAMLResponse]: {Request.Form["SAMLResponse"]}");
                    samlResponse.LoadXmlFromBase64(Request.Form["SAMLResponse"]); 
                    Logger.Debug($"CorrelationId={correlationId}. SAML response: {samlResponse.Xml}");

                    if (!samlResponse.IsValid())
                    {
                        throw new ApplicationException("SAML response is not valid");
                    }

                    Logger.Trace($"CorrelationId={correlationId}. SAML response is valid. User logged in!");

                    // Process claims
                    string username = "", email = "", firstname = "", lastname = "", displayname = "";
                    var rolesList = new List<string>();
                    var ignoredRolesList = new List<string>();
                    try
                    {
                        username = samlResponse.GetUserProperty(config.usrUserName, "username");
                        if (string.IsNullOrEmpty(username))
                        {
                            username = samlResponse.GetNameID();
                        }                        
                        email = samlResponse.GetUserProperty(config.usrEmail, "email");
                        firstname = samlResponse.GetUserProperty(config.usrFirstName, "firstName");
                        lastname = samlResponse.GetUserProperty(config.usrLastName, "lastName");
                        displayname = samlResponse.GetUserProperty(config.usrDisplayName, "displayName");

                        // Ensure first and last name and displayname are not empty. This usually happens with Entra ID guest users
                        if (string.IsNullOrEmpty(displayname))
                        {
                            displayname = $"{firstname} {lastname}".Trim();
                        }
                        if (string.IsNullOrEmpty(firstname))
                        {
                            firstname = StaticHelper.GetFirstName(displayname);
                        }
                        if (string.IsNullOrEmpty(lastname))
                        {
                            lastname = StaticHelper.GetLastName(displayname);
                        }

                        StaticHelper.EnsureNotEmpty(nameof(username), username, Logger, correlationId);
                        StaticHelper.EnsureNotEmpty(nameof(email), email, Logger, correlationId);
                        StaticHelper.EnsureNotEmpty(nameof(firstname), firstname, Logger, correlationId);
                        StaticHelper.EnsureNotEmpty(nameof(lastname), lastname, Logger, correlationId);
                        StaticHelper.EnsureNotEmpty(nameof(displayname), displayname, Logger, correlationId);

                        var roles = samlResponse.GetUserProperty(config.RoleAttribute);
                        if (!string.IsNullOrWhiteSpace(roles))
                        {
                            roles = roles.Replace(';', ',');
                            rolesList = roles.Split(new []{','}, StringSplitOptions.RemoveEmptyEntries).ToList();
                        }

                        var ignoredRoles = config.IgnoredRoles;
                        if (!string.IsNullOrWhiteSpace(ignoredRoles))
                        {
                            ignoredRoles.Replace(';', ',');
                            ignoredRolesList = ignoredRoles.Split(new[] {','},
                                StringSplitOptions.RemoveEmptyEntries).ToList();
                        }
                        // Remove ignored roles from rolesList
                        rolesList = rolesList.Except(ignoredRolesList).ToList();
                    }
                    catch (Exception ex)
                    {                            
                        throw new ApplicationException("Error processing SAML claims", ex);
                    }

                    // Now we have the user's info, let's create or update the user
                    UserInfo userInfo = UserController.GetUserByName(PortalSettings.PortalId, username);                            
                    if (userInfo == null) 
                    {                   
                        Logger.Debug($"CorrelationId={correlationId}. User does not exist, let's create it");
                        try
                        {
                            userInfo = new UserInfo()
                            {
                                FirstName = firstname,
                                LastName = lastname,
                                DisplayName = displayname,
                                Email = email,
                                Username = username,
                                PortalID = PortalSettings.PortalId,
                                IsSuperUser = false,
                                Membership = new UserMembership()
                                {
                                    Password = UserController.GeneratePassword()
                                }
                            };
                                           
                            UserCreateStatus usrCreateStatus = UserController.CreateUser(ref userInfo);
                            if (usrCreateStatus == UserCreateStatus.Success)
                            {
                                UserInfo usrInfo = UserController.GetUserByName(PortalSettings.PortalId, username);
                                SetProfileProperties(config, samlResponse, usrInfo);
                                UpdateUserMembership(usrInfo);

                                //Add roles if needed, since a new user no need to remove roles or process that condition
                                if (rolesList.Any())
                                    AssignRolesFromList(usrInfo, rolesList);
                            }
                            else
                            {
                                throw new ApplicationException($"Error creating new user: {usrCreateStatus}");
                            }                                                                                
                        }
                        catch (Exception ex)
                        {
                            throw new ApplicationException("Error creating new user", ex);
                        }                                
                    }
                    else // User exists, let's update it
                    {
                        Logger.Debug($"CorrelationId={correlationId}. User exists, let's update it");
                        try
                        {                             
                            userInfo.DisplayName = displayname;
                            userInfo.FirstName = firstname;
                            userInfo.LastName = lastname;
                            userInfo.Email = email;
                            UserController.UpdateUser(PortalSettings.PortalId, userInfo);

                            SetProfileProperties(config, samlResponse, userInfo);
                            UpdateUserMembership(userInfo);

                            // If we have a role list, assign the roles
                            if (rolesList.Any())
                            {
                                AssignRolesFromList(userInfo, rolesList);
                            }
                            // Loop user roles and remove the roles that are not in the list
                            var rolesToRemove = userInfo.Roles.Where(r => !rolesList.Contains(r)).ToList();
                            RemoveRolesFromList(userInfo, rolesToRemove);
                        }
                        catch (Exception ex)
                        {
                            throw new ApplicationException("Error updating the user", ex);

                        }                               
                    }
                            
                    // Validate user
                    UserValidStatus validStatus = UserController.ValidateUser(userInfo, PortalId, true);
                    UserLoginStatus loginStatus = validStatus == UserValidStatus.VALID ? UserLoginStatus.LOGIN_SUCCESS : UserLoginStatus.LOGIN_FAILURE;
                    if (loginStatus == UserLoginStatus.LOGIN_SUCCESS)
                    {

                        // Obtain the current client IP
                        var userRequestIpAddressController = UserRequestIPAddressController.Instance;
                        var ipAddress = userRequestIpAddressController.GetUserRequestIPAddress(new HttpRequestWrapper(this.Request));

                        // check if the user is an admin/host and validate their IP
                        if (Host.EnableIPChecking)
                        {
                            bool isAdminUser = userInfo.IsSuperUser || userInfo.IsInRole(this.PortalSettings.AdministratorRoleName);
                            if (isAdminUser)
                            {
                                var clientIp = ipAddress;
                                if (IPFilterController.Instance.IsIPBanned(clientIp))
                                {
                                    PortalSecurity.Instance.SignOut();
                                    this.AddModuleMessage("IPAddressBanned", ModuleMessage.ModuleMessageType.RedError, true);
                                    return;
                                }
                            }
                        }

                        // Set the Page Culture(Language) based on the Users Preferred Locale
                        if ((userInfo.Profile != null) && (userInfo.Profile.PreferredLocale != null) && this.LocaleEnabled(userInfo.Profile.PreferredLocale))
                        {
                            Localization.SetLanguage(userInfo.Profile.PreferredLocale);
                        }
                        else
                        {
                            Localization.SetLanguage(this.PortalSettings.DefaultLanguage);
                        }

                        // Set the Authentication Type used
                        AuthenticationController.SetAuthenticationType(this.AuthenticationType);

                        // Complete Login
                        UserController.UserLogin(this.PortalId, userInfo, this.PortalSettings.PortalName, ipAddress, false);


                        // redirect browser
                        if (!string.IsNullOrEmpty(config.RedirectURL))
                        {
                            this.RedirectURL = config.RedirectURL;
                        }
                        var redirectUrl = this.RedirectURL;

                        // Clear the cookie
                        HttpContext.Current.Response.Cookies.Set(new HttpCookie("returnurl", string.Empty)
                        {
                            Expires = DateTime.Now.AddDays(-1),
                            Path = !string.IsNullOrEmpty(Globals.ApplicationPath) ? Globals.ApplicationPath : "/",
                        });

                        this.Response.Redirect(redirectUrl, false);                                                        
                    } 
                }
                else
                {
                    Logger.Trace($"CorrelationId={correlationId}. Redirecting to SAML provider");
                    SAMLAuthenticationConfig config = SAMLAuthenticationConfig.GetConfig(PortalId);
                    XmlDocument request = GenerateSAMLRequest(config, correlationId);

                    string convertedSigAlg = "";
                    string convertedSignature = "";
                    string relayState = "NA";
                    if (Request.QueryString.Count > 0)
                    {
                        relayState = HttpUtility.UrlEncode(Request.Url.Query.Replace("?", "&"));
                    }
                    String convertedRequestXML = StaticHelper.Base64CompressUrlEncode(request);
                    if (!string.IsNullOrEmpty(config.OurCert) && !string.IsNullOrEmpty(config.OurCertKey))
                    {
                        // Signed requests are done via POST
                        Logger.Trace($"CorrelationId={correlationId}. Signing SAML request with our certificate");
                        X509Certificate2 cert = StaticHelper.LoadCertificateFromPEM(config.OurCert, config.OurCertKey);
                        Logger.Trace($"CorrelationId={correlationId}. Certificate loaded successfully, Serial Number:{cert.SerialNumber}");
                        request = StaticHelper.SignSAMLRequest2(request, cert);
                        convertedRequestXML = Convert.ToBase64String(Encoding.UTF8.GetBytes(request.OuterXml)); // StaticHelper.Base64CompressUrlEncode(request);
                        convertedSigAlg = HttpUtility.UrlEncode("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
                        byte[] signature = StaticHelper.SignString2(string.Format("RelayState={0}&SigAlg={1}", relayState, convertedSigAlg), config.OurCertKey);
                        convertedSignature = HttpUtility.UrlEncode(Convert.ToBase64String(signature));

                        Logger.Debug($"CorrelationId={correlationId}. Posting to SAML provider. SAMLRequest={convertedRequestXML}");
                        redirectTo = config.IdPURL + (config.IdPURL.Contains("?") ? "&" : "?") + "RelayState=" + relayState + "&SigAlg=" + convertedSigAlg  +"&Signature=" + convertedSignature;                        
                        File.WriteAllText(Path.Combine(Path.GetTempPath(), correlationId), convertedRequestXML);
                        Response.Redirect($"/api/saml/sso/process?sid={correlationId}&state={relayState}&sigalg={convertedSigAlg}&signature={convertedSignature}", false);

                        /*Response.Write("<html><head><script type='text/javascript'>window.onload = function() {document.forms[0].submit();}</script></head><body><form method='post' action='" + redirectTo + "'>" +
                            "<input type='hidden' name='SAMLRequest' value='" + convertedRequestXML + "' />" +
                            "<input type='submit' value='Submit' /></form></body></html>");*/
                    }          
                    else // Not signed requests are done via GET
                    {
                        Logger.Debug($"CorrelationId={correlationId}. Redirecting to SAML provider. SAMLRequest={convertedRequestXML}");
                        redirectTo = config.IdPURL + (config.IdPURL.Contains("?") ? "&" : "?") + "SAMLRequest=" + convertedRequestXML;
                        if (Request.QueryString.Count > 0)
                            redirectTo += $"&RelayState={relayState}";
                        Response.Redirect(Page.ResolveUrl(redirectTo), false);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"CorrelationId={correlationId}", ex);
                LogAdminAlertToEventLog("DotNetNuke.Authentication.SAML.OnLoad()", $"CorrelationId={correlationId}; Exception: {ex.Message}; Inner: {ex.InnerException?.Message}");
                UI.Skins.Skin.AddModuleMessage(this, $"Error processing SAML claims. CorrelationId={correlationId}", ModuleMessage.ModuleMessageType.RedError);
            }
        }

        private bool LocaleEnabled(string locale)
        {
            return LocaleController.Instance.GetLocales(this.PortalSettings.PortalId).ContainsKey(locale);
        }

        private XmlDocument GenerateSAMLRequest(SAMLAuthenticationConfig config, string correlationId)
        {
            DateTime now = DateTime.SpecifyKind(DateTime.Now, DateTimeKind.Utc);
            string authnRequestID = "DNN_SAML_" + correlationId.Replace("-", "");

            string requestXML = @"<samlp:AuthnRequest " +
                @" ID=""" + authnRequestID + @"""" +
                @" IssueInstant = """ + now.ToString("O") + @"""" +
                @" Version = ""2.0"" " +
                @" Destination = """ + config.IdPURL + @"""" +
                @" ForceAuthn = ""false"" " +
                @" IsPassive = ""false"" " +
                @" ProtocolBinding = ""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"" " +
                @" AssertionConsumerServiceURL = """ + config.ConsumerServURL + @"""" +
                @" xmlns:samlp = ""urn:oasis:names:tc:SAML:2.0:protocol"">" +
                @" <saml:Issuer xmlns:saml = ""urn:oasis:names:tc:SAML:2.0:assertion"">" + config.OurIssuerEntityID + @"</saml:Issuer>" +
                @" </samlp:AuthnRequest>";

            XmlDocument xml = new XmlDocument();
            xml.LoadXml(requestXML);
            return xml;
        }

        private void SetProfileProperties(SAMLAuthenticationConfig config, Saml.Response response, UserInfo uInfo)
        {
            try
            {
                Dictionary<string, string> properties = new Dictionary<string, string>();
                ProfilePropertyDefinitionCollection props = ProfileController.GetPropertyDefinitionsByPortal(PortalSettings.PortalId);
                foreach (ProfilePropertyDefinition def in props)
                {
                    string SAMLPropertyName = config.getProfilePropertySAMLName(def.PropertyName);
                    if(SAMLPropertyName != "")
                    {
                        properties.Add(def.PropertyName, response.GetUserProperty(SAMLPropertyName));
                    }                    
                }

                foreach (KeyValuePair<string, string> kvp in properties)
                {
                    uInfo.Profile.SetProfileProperty(kvp.Key, kvp.Value);
                }

                ProfileController.UpdateUserProfile(uInfo);
            }
            catch (Exception ex)
            {
                Logger.Error($"Error updating profile properties for user {uInfo.Username}", ex);
            }
        }

        private void MarkUserAsSaml(UserInfo user)
        {
            var def = ProfileController.GetPropertyDefinitionByName(user.PortalID, "IdentitySource");
            if (def == null)
            {
                var dataTypes = (new ListController()).GetListEntryInfoDictionary("DataType");
                var definition = new ProfilePropertyDefinition(user.PortalID)
                {
                    DataType = dataTypes["DataType:Text"].EntryID,
                    DefaultValue = "SAML",
                    DefaultVisibility = UserVisibilityMode.AdminOnly,
                    PortalId = user.PortalID,
                    ModuleDefId = Null.NullInteger,
                    PropertyCategory = "Security",
                    PropertyName = "IdentitySource",
                    Required = false,
                    Visible = false,
                    ViewOrder = -1
                };
                ProfileController.AddPropertyDefinition(definition);
            }

            user.Profile.SetProfileProperty("IdentitySource", "SAML");
            Security.Profile.ProfileProvider.Instance().UpdateUserProfile(user);
        }

        private void UpdateUserMembership(UserInfo userInfo)
        {
            // Unlock user if necessary
            if (userInfo.Membership.LockedOut)
            {
                UserController.UnLockUser(userInfo);
            }

            // Reset user password with a new one to avoid password expiration errors on DNN for SAML users
            MembershipUser aspnetUser = Membership.GetUser(userInfo.Username);
            aspnetUser.ResetPassword();

            // Last login date not being updated by DNN on OAuth login, so we have to do it manually
            aspnetUser = Membership.GetUser(userInfo.Username);
            aspnetUser.LastLoginDate = DateTime.Now;
            Membership.UpdateUser(aspnetUser);

            // Updates the user in DNN
            userInfo.Membership.LastLoginDate = aspnetUser.LastLoginDate;
            userInfo.Membership.UpdatePassword = false;
            userInfo.Membership.Approved = true; // Delegate approval on Auth Provider
            UserController.UpdateUser(userInfo.PortalID, userInfo);

            MarkUserAsSaml(userInfo);
        }

        #region Role Helpers
        private RoleInfo GetOrCreateRole(string roleName)
        {
            //Get the role
            var role = RoleController.Instance.GetRoleByName(PortalId, roleName);
            if (role != null)
                return role;

            //If not found, create it
            var toCreate = new RoleInfo
            {
                AutoAssignment = false,
                Description = "Added from SAML Login",
                IsPublic = false,
                PortalID = PortalId,
                RoleGroupID = Null.NullInteger,
                RoleName = roleName,
                SecurityMode = SecurityMode.SecurityRole,
                Status = RoleStatus.Approved
            };
            RoleController.Instance.AddRole(toCreate);
            return RoleController.Instance.GetRoleByName(PortalId, roleName);
        }

        /// <summary>
        /// Assigns roles
        /// </summary>
        /// <param name="user"></param>
        /// <param name="oRolesToAssign"></param>
        private void AssignRolesFromList(UserInfo user, List<string> oRolesToAssign)
        {
            if (oRolesToAssign != null && oRolesToAssign.Count > 0)
            {
                //Loop through each assignment, and see if we need to add
                foreach (var oCurrent in oRolesToAssign)
                {
                    //Make sure that the user needs it
                    if (!user.IsInRole(oCurrent))
                    {
                        //Get role info
                        var oCurrentRole = GetOrCreateRole(oCurrent);

                        //Assign it
                        RoleController.Instance.AddUserRole(PortalId, user.UserID, oCurrentRole.RoleID,
                            RoleStatus.Approved, false, DateTime.Now.AddDays(-1), Null.NullDate);
                    }
                }
            }
        }

        /// <summary>
        /// Removes the roles from a user, based on a list of roles to remove
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="oRolesToRemove">The o roles to remove.</param>
        private void RemoveRolesFromList(UserInfo user, List<string> oRolesToRemove)
        {
            if (oRolesToRemove != null && oRolesToRemove.Count > 0)
            {
                foreach (var oCurrent in oRolesToRemove)
                {
                    //Only remove if the user is in it
                    if (user.IsInRole(oCurrent))
                    {
                        var oCurrentRole = RoleController.Instance.GetRoleByName(PortalId, oCurrent);
                        RoleController.DeleteUserRole(user, oCurrentRole, PortalSettings, false);
                    }
                }
            }
        }
        #endregion 
    }
}



