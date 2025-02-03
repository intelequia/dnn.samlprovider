using DotNetNuke.Common.Utilities;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Services.Authentication;
using System;


namespace DotNetNuke.Authentication.SAML
{

    [Serializable]
    public class SAMLAuthenticationConfig : AuthenticationConfigBase
    {
        internal const string AuthTypeName = "SAML";
        internal const string PREFIX = "SAML_";
        internal const string usrPREFIX = "usr_";
        protected SAMLAuthenticationConfig(int portalID) : base(portalID)
        {
            this.PortalID = portalID;
            Enabled = true;
            string setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "Enabled", out setting))
                Enabled = bool.Parse(setting);

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "IdPURL", out setting))
                IdPURL = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "IdPLogoutURL", out setting))
                IdPLogoutURL = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "OurIssuerEntityID", out setting))
                OurIssuerEntityID = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "ConsumerServURL", out setting))
                ConsumerServURL = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "TheirCert", out setting))
                TheirCert = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + usrPREFIX + "Username", out setting))
                usrUserName = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + usrPREFIX + "FirstName", out setting))
                usrFirstName = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + usrPREFIX + "LastName", out setting))
                usrLastName = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + usrPREFIX + "DisplayName", out setting))
                usrDisplayName = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + usrPREFIX + "Email", out setting))
                usrEmail = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID)
                .TryGetValue(PREFIX + usrPREFIX + "RoleAttribute", out setting))
                RoleAttribute = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID)
                .TryGetValue(PREFIX + usrPREFIX + "IgnoredRoles", out setting))
                IgnoredRoles = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "RedirectURL", out setting))
                RedirectURL = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "OurCert", out setting))
                OurCert = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "OurCertKey", out setting))
                OurCertKey = setting;
        }

        public bool Enabled { get; set; }
        public string IdPURL { get; set; }
        public string IdPLogoutURL { get; set; }
        public string OurIssuerEntityID { get; set; }
        public string ConsumerServURL { get; set; }
        public string TheirCert { get; set; }
        public string OurCert { get; set; }
        public string OurCertKey { get; set; }
        public string RedirectURL { get; set; }

        public string usrFirstName { get; set; }
        public string usrLastName { get; set; }
        public string usrDisplayName { get; set; }
        public string usrUserName { get; set; }
        public string usrEmail { get; set; }

        public string RoleAttribute { get; set; }
        public string IgnoredRoles { get; set; }


        public static SAMLAuthenticationConfig GetConfig(int portalId)
        {
            return new SAMLAuthenticationConfig(portalId);
        }

        public static void UpdateConfig(SAMLAuthenticationConfig config)
        {
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "Enabled", config.Enabled.ToString());
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "IdPURL", config.IdPURL);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "IdPLogoutURL", config.IdPLogoutURL);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "OurIssuerEntityID", config.OurIssuerEntityID);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "ConsumerServURL", config.ConsumerServURL);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "TheirCert", config.TheirCert);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "OurCert", config.OurCert);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "OurCertKey", config.OurCertKey);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "RedirectURL", config.RedirectURL);

            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + usrPREFIX + "Username", config.usrUserName);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + usrPREFIX + "FirstName", config.usrFirstName);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + usrPREFIX + "LastName", config.usrLastName);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + usrPREFIX + "DisplayName", config.usrDisplayName);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + usrPREFIX + "Email", config.usrEmail);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + usrPREFIX + "RoleAttribute", config.RoleAttribute);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + usrPREFIX + "IgnoredRoles", config.IgnoredRoles);
        }

        public string getProfilePropertySAMLName(string DNNpropertyName)
        {
            var setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(PortalID).TryGetValue(PREFIX + usrPREFIX + DNNpropertyName, out setting))
            {
                return setting;
            }
            return "";
        }


    }
}