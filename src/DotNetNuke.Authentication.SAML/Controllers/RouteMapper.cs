using DotNetNuke.Web.Api;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web;

namespace DotNetNuke.Authentication.SAML.Controllers
{
    public class RouteMapper : IServiceRouteMapper
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="routeManager"></param>
        public void RegisterRoutes(IMapRoute routeManager)
        {
            routeManager.MapHttpRoute("SAML", "default", "{controller}/{action}", new[] { "DotNetNuke.Authentication.SAML.Controllers" });
        }

    }
}