using Saml;

namespace DotNetNuke.Authentication.SAML.Extensions
{
    public static class SamlExtensions
    {
        public static string GetUserProperty(this Response response, string propertyName, string defaultPropertyName = "")
        {
            string result = response.GetCustomAttribute(propertyName);
            if (string.IsNullOrEmpty(result))
            {
                result = response.GetCustomAttribute(defaultPropertyName);
            }
            return result;
            //XmlNode node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='" + propertyName + "']/saml:AttributeValue", _xmlNameSpaceManager);
            //return node == null ? null : node.InnerText;
        }


    }
}