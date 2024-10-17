using DotNetNuke.Entities.Users;
using DotNetNuke.Instrumentation;
using DotNetNuke.Services.Authentication;
using DotNetNuke.UI.Skins.Controls;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace DotNetNuke.Authentication.SAML
{
    public partial class Logoff : AuthenticationLogoffBase
    {
        private static readonly ILog Logger = LoggerSource.Instance.GetLogger(typeof(Logoff));

        protected override void OnInit(EventArgs e)
        {
            try
            {
                string correlationId = Guid.NewGuid().ToString();
                base.OnInit(e);
                var userInfo = UserController.Instance.GetCurrentUserInfo();
                if (userInfo == null)
                {
                    return;                    
                }
                base.OnLogOff(e);
                this.AuthenticationType = "SAML";
                Logger.Trace($"Logoff.OnInit(): Logging off from saml '{userInfo.Username}'. CorrelationId={correlationId}");

                SAMLAuthenticationConfig config = SAMLAuthenticationConfig.GetConfig(PortalId);

                XmlDocument request = GenerateSAMLLogoffRequest(userInfo.Username, config);
                string convertedRequestXML = StaticHelper.Base64CompressUrlEncode(request.OuterXml);

                string convertedSigAlg = "";
                string convertedSignature = "";
                if (!string.IsNullOrEmpty(config.OurCert) && !string.IsNullOrEmpty(config.OurCertKey))
                {
                    Logger.Trace($"CorrelationId={correlationId}. Signing SAML request with our certificate");
                    X509Certificate2 cert = StaticHelper.LoadCertificateFromPEM(config.OurCert, config.OurCertKey);
                    Logger.Trace($"CorrelationId={correlationId}. Certificate loaded successfully, Serial Number:{cert.SerialNumber}");
                    request = StaticHelper.SignSAMLRequest2(request, cert);
                    convertedSigAlg = System.Web.HttpUtility.UrlEncode("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
                    byte[] signature = StaticHelper.SignString2(string.Format("SAMLRequest={0}&RelayState={1}&SigAlg={2}", convertedRequestXML, "NA", convertedSigAlg), config.OurCertKey);
                    convertedSignature = System.Web.HttpUtility.UrlEncode(Convert.ToBase64String(signature));
                }
                string redirectTo = config.IdPLogoutURL +
                    "?SAMLRequest=" + convertedRequestXML +
                    "&RelayState=NA";
                if (!string.IsNullOrEmpty(convertedSigAlg))
                {
                    redirectTo += "&SigAlg=" + convertedSigAlg;
                }
                if (!string.IsNullOrEmpty(convertedSignature))
                {
                    redirectTo += "&Signature=" + convertedSignature;
                }
                Response.Redirect(redirectTo, false);
            }
            catch (Exception ex)
            {
                Logger.Error(ex);
                UI.Skins.Skin.AddModuleMessage(this, $"Error logging out.", ModuleMessage.ModuleMessageType.RedError);
            }

        }        

        private XmlDocument GenerateSAMLLogoffRequest(string userName, SAMLAuthenticationConfig config)
        {
            DateTime now = DateTime.SpecifyKind(DateTime.Now, DateTimeKind.Utc);
            string authnRequestID = "_" + Guid.NewGuid().ToString().Replace("-", "");

            string requestXML = @"<samlp:LogoutRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" " +
                @" ID=""" + authnRequestID + @"""" +
                @" Version=""2.0"" " +
                @" IssueInstant=""" + now.ToString("O") + @"""" +
                @" Reason=""urn:oasis:names:tc:SAML:2.0:logout:user""" +
                @" Destination=""" + config.IdPLogoutURL + @""" >" +
                @" <saml:Issuer xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">" + config.OurIssuerEntityID + @"</saml:Issuer>" +
                @" <saml:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"">" + userName + @"</saml:NameID>" +
                //@" <samlp:SessionIndex>" + Session["sessionIndexFromSAMLResponse"] + "</samlp:SessionIndex>" +
                @" </samlp:LogoutRequest>
          ";

            XmlDocument xml = new XmlDocument();
            xml.LoadXml(requestXML);
            return xml;
        }

    }
}  
   