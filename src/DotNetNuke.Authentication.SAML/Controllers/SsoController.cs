using DotNetNuke.Common.Utilities;
using DotNetNuke.Services.Mobile;
using DotNetNuke.Web.Api;
using Saml;
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Web;
using System.Web.Http;
using System.Xml;

namespace DotNetNuke.Authentication.SAML.Controllers
{
    public class SsoController: DnnApiController
    {
        [HttpGet]
        [AllowAnonymous]
        public HttpResponseMessage Process(string sid, string state, string sigalg, string signature)
        {
            string filename = string.Empty;
            try
            {
                if (string.IsNullOrEmpty(sid))
                {
                    return Request.CreateResponse(HttpStatusCode.NotFound, "Request not found");
                }

                filename = Path.Combine(Path.GetTempPath(), sid);
                if (!File.Exists(filename) || !(File.GetCreationTimeUtc(filename) > DateTime.UtcNow.AddMinutes(-1)))
                {
                    return Request.CreateResponse(HttpStatusCode.NotFound, "Request not found");
                }
                string samlRequest = File.ReadAllText(filename);
                SAMLAuthenticationConfig config = SAMLAuthenticationConfig.GetConfig(PortalSettings.PortalId);
                string extraParams = "RelayState=" + HttpUtility.UrlEncode(state)+ "&SigAlg=" + HttpUtility.UrlEncode(sigalg) + "&Signature=" + HttpUtility.UrlEncode(signature);
                string redirectTo = config.IdPURL + (config.IdPURL.Contains("?") 
                    ? HttpUtility.UrlEncode("&" + extraParams) //(config.IdPURL.ToLowerInvariant().Contains("returnurl=") 
                        //? HttpUtility.UrlEncode("&" + extraParams)
                        //: "&" + extraParams)
                    : "?" + extraParams);
                string content = "<html><head><script type='text/javascript'>window.onload = function() {document.forms[0].submit();}</script></head><body><form method='post' action='" + redirectTo + "'>" +
                "<input type='hidden' name='SAMLRequest' value='" + samlRequest + "' />" +
                "</form></body></html>";


                HttpResponseMessage result = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(content, System.Text.Encoding.UTF8, "text/html")
                };
                return result;
            }
            catch (Exception ex)
            {
                return Request.CreateResponse(HttpStatusCode.InternalServerError, ex.Message);
            }
            finally
            {
                if (!string.IsNullOrEmpty(filename) && File.Exists(filename))
                {
                    File.Delete(filename);
                }
            }
        }
    }
}