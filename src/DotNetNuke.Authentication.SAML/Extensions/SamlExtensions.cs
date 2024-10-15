using Saml;

namespace DotNetNuke.Authentication.SAML.Extensions
{
    public static class SamlExtensions
    {
        public static string GetUserProperty(this Response response, string propertyName)
        {
            return response.GetCustomAttribute(propertyName);
            //XmlNode node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='" + propertyName + "']/saml:AttributeValue", _xmlNameSpaceManager);
            //return node == null ? null : node.InnerText;
        }
    }
}