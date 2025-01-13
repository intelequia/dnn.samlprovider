using DotNetNuke.Common.Utilities;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Entities.Profile;
using DotNetNuke.Services.Authentication;
using DotNetNuke.Services.Exceptions;
using System;
using System.Data;
using System.Web.UI.WebControls;

namespace DotNetNuke.Authentication.SAML
{
    public partial class Settings : AuthenticationSettingsBase
    {
        public override void UpdateSettings()
        {
            try
            {

                var config = SAMLAuthenticationConfig.GetConfig(PortalId);
                config.PortalID = PortalId;
                config.ConsumerServURL = txtConsumerServUrl.Text;
                config.Enabled = chkEnabled.Checked;
                config.IdPLogoutURL = txtIdpLogoutUrl.Text;
                config.IdPURL = txtIdpUrl.Text;
                config.OurIssuerEntityID = txtOurIssuerEntityId.Text;
                config.TheirCert = txtTheirCert.Text;
                config.OurCert = txtOurCert.Text;
                config.OurCertKey = txtOurCertKey.Text;
                config.usrUserName = txtUsername.Text;
                config.usrDisplayName = txtDisplayName.Text;
                config.usrEmail = txtEmail.Text;
                config.usrFirstName = txtFirstName.Text;
                config.usrLastName = txtLastName.Text;
                config.RoleAttribute = txtRoleAttributeName.Text;
                config.IgnoredRoles = txtIgnoredRolesTextbox.Text;
                config.RedirectURL = txtRedirectURL.Text;

                SAMLAuthenticationConfig.UpdateConfig(config);

                //Iterate through repeater
                foreach (RepeaterItem item in repeaterProps.Items)
                {
                    if (item.ItemType == ListItemType.Item || item.ItemType == ListItemType.AlternatingItem)
                    {
                        Label lblProperty = (Label)item.FindControl("lblProperty");
                        TextBox txtMapped = (TextBox)item.FindControl("txtMappedValue");
                        PortalController.UpdatePortalSetting(config.PortalID, SAMLAuthenticationConfig.PREFIX + SAMLAuthenticationConfig.usrPREFIX + lblProperty.Text, txtMapped.Text);
                    }
                }

            }
            catch (Exception exc)
            {
                Exceptions.ProcessModuleLoadException(this, exc);
            }
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);

            try
            {
                if (!this.IsPostBack)
                {
                    var config = SAMLAuthenticationConfig.GetConfig(PortalId);
                    txtIdpUrl.Text = config.IdPURL;
                    txtIdpLogoutUrl.Text = config.IdPLogoutURL;
                    txtConsumerServUrl.Text = config.ConsumerServURL;
                    txtUsername.Text = config.usrUserName;
                    txtDisplayName.Text = config.usrDisplayName;
                    txtEmail.Text = config.usrEmail;
                    txtFirstName.Text = config.usrFirstName;
                    txtLastName.Text = config.usrLastName;
                    txtOurIssuerEntityId.Text = config.OurIssuerEntityID;
                    txtTheirCert.Text = config.TheirCert;
                    txtOurCert.Text = config.OurCert;
                    txtOurCertKey.Text = config.OurCertKey;
                    chkEnabled.Checked = config.Enabled;
                    txtRoleAttributeName.Text = config.RoleAttribute;
                    txtIgnoredRolesTextbox.Text = config.IgnoredRoles;
                    txtRedirectURL.Text = config.RedirectURL;
                }
                BindRepeater();

            }
            catch (Exception exc)
            {
                Exceptions.ProcessModuleLoadException(this, exc);
            }
        }

        private void BindRepeater()
        {
            var ds = new DataSet();
            var dt = ds.Tables.Add("Properties");
            dt.Columns.Add("Property", typeof(string));
            dt.Columns.Add("Mapping", typeof(string));

            var props = ProfileController.GetPropertyDefinitionsByPortal(PortalId);
            foreach (ProfilePropertyDefinition def in props)
            {
                if (def.PropertyName == "UserName" || def.PropertyName == "FirstName" || def.PropertyName == "LastName" || def.PropertyName == "IdentitySource")
                {
                    continue;
                }

                var setting = Null.NullString;
                var row = ds.Tables[0].NewRow();
                row[0] = def.PropertyName;
                if (PortalController.Instance.GetPortalSettings(PortalId).TryGetValue(SAMLAuthenticationConfig.PREFIX + SAMLAuthenticationConfig.usrPREFIX + def.PropertyName, out setting))
                {
                    row[1] = setting;
                }
                else
                {
                    row[1] = "";
                }
                ds.Tables[0].Rows.Add(row);
            }

            repeaterProps.DataSource = ds;
            repeaterProps.DataBind();
        }
    }
}

