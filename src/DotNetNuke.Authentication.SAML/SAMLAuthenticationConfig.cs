using DotNetNuke.Common.Utilities;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Services.Authentication;
using System;


namespace DotNetNuke.Authentication.SAML
{

    [Serializable]
    public class SAMLAuthenticationConfig : AuthenticationConfigBase
    {
        internal const string PREFIX = "DNN.Authentication.SAML_";
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

            DNNAuthName = "SAML";
            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "DNNAuthName", out setting))
                DNNAuthName = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "TheirCert", out setting))
                TheirCert = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(usrPREFIX + "FirstName", out setting))
                usrFirstName = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(usrPREFIX + "LastName", out setting))
                usrLastName = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(usrPREFIX + "DisplayName", out setting))
                usrDisplayName = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(usrPREFIX + "Email", out setting))
                usrEmail = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID)
                .TryGetValue(usrPREFIX + "RoleAttribute", out setting))
                RoleAttribute = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID)
                .TryGetValue(usrPREFIX + "RequiredRoles", out setting))
                RequiredRoles = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "RedirectURL", out setting))
                RedirectURL = setting;
        }

        public bool Enabled { get; set; }
        public string IdPURL { get; set; }
        public string IdPLogoutURL { get; set; }
        public string OurIssuerEntityID { get; set; }
        public string ConsumerServURL { get; set; }
        public string DNNAuthName { get; set; }
        public string TheirCert { get; set; }
        public string RedirectURL { get; set; }

        public string usrFirstName { get; set; }
        public string usrLastName { get; set; }
        public string usrDisplayName { get; set; }
        public string usrEmail { get; set; }

        public string RoleAttribute { get; set; }
        public string RequiredRoles { get; set; }


        public static SAMLAuthenticationConfig GetConfig(int portalId)
        {
            var config = new SAMLAuthenticationConfig(portalId);
            return config;
        }

        public static void UpdateConfig(SAMLAuthenticationConfig config)
        {
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "Enabled", config.Enabled.ToString());
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "IdPURL", config.IdPURL);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "IdPLogoutURL", config.IdPLogoutURL);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "OurIssuerEntityID", config.OurIssuerEntityID);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "ConsumerServURL", config.ConsumerServURL);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "DNNAuthName", config.DNNAuthName);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "TheirCert", config.TheirCert);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "RedirectURL", config.RedirectURL);

            //ClearConfig(config.PortalID);
            PortalController.UpdatePortalSetting(config.PortalID, usrPREFIX + "FirstName", config.usrFirstName);
            PortalController.UpdatePortalSetting(config.PortalID, usrPREFIX + "LastName", config.usrLastName);
            PortalController.UpdatePortalSetting(config.PortalID, usrPREFIX + "DisplayName", config.usrDisplayName);
            PortalController.UpdatePortalSetting(config.PortalID, usrPREFIX + "Email", config.usrEmail);
            PortalController.UpdatePortalSetting(config.PortalID, usrPREFIX + "RoleAttribute", config.RoleAttribute);
            PortalController.UpdatePortalSetting(config.PortalID, usrPREFIX + "RequiredRoles", config.RequiredRoles);
        }

        public string getProfilePropertySAMLName(string DNNpropertyName)
        {
            var setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(PortalID).TryGetValue(usrPREFIX + DNNpropertyName + ":", out setting))
            {
                return setting;
            }
            else
            {
                return "";
            }
        }


    }
}