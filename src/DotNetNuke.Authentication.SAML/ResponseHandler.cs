using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using DotNetNuke.Instrumentation;

namespace DotNetNuke.Authentication.SAML
{

    public class ResponseHandler
    {
        private static readonly ILog Logger = LoggerSource.Instance.GetLogger(typeof(ResponseHandler));

        protected XmlDocument xmlDocResponse;
        protected X509Certificate2 myCert;
        protected X509Certificate2 theirCert;

        public ResponseHandler(string rawResponse, X509Certificate2 myCert, string theirCertString) : this(rawResponse, myCert)
        {
            this.theirCert = new X509Certificate2();
            theirCert.Import(StaticHelper.StringToByteArray(theirCertString));
        }

        public ResponseHandler (string rawResponse, X509Certificate2 myCert, X509Certificate2 theirCert) : this (rawResponse, myCert)
        {
            this.theirCert = theirCert;
        }
        private ResponseHandler(string rawResponse, X509Certificate2 myCert)
        {
            this.myCert = myCert;
      
            ASCIIEncoding enc = new ASCIIEncoding();
            this.xmlDocResponse = new XmlDocument();
            this.xmlDocResponse.PreserveWhitespace = true;
            this.xmlDocResponse.XmlResolver = null;
            this.xmlDocResponse.LoadXml(rawResponse);

            if (DoesNeedToBeDecrypted())
            {
                //Login.LogToEventLog("ResponseHandler(encrypted)","ResponseHandler(encrypted) : enter");

                //get cipher key
                var decodedCipherKey = GetCipherKey(xmlDocResponse, myCert);
                //Login.LogToEventLog("ResponseHandler(encrypted)","ResponseHandler(encrypted) : cipherKey : " + decodedCipherKey);

                //get encrypted data
                XmlNode node = GetNode("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue");
                if (node == null)
                    throw new Exception("CipherValue node not found");

                string cipherValue = node.InnerText;
                //LogToEventLog("ResponseHandler(encrypted)","GetNameID(encrypted) : ciphervalue {0}", cipherValue);

                EncryptionHelper encryptionHelper = new EncryptionHelper(decodedCipherKey);
                string decryptedValue = encryptionHelper.AesDecrypt(cipherValue);
                Logger.Debug("ResponseHandler(encrypted) : Response : " + xmlDocResponse.OuterXml);
                Logger.Debug("ResponseHandler(encrypted) : decryptedValue : " + decryptedValue);

                //add decrypted assertion node to the document
                XmlDocumentFragment xfrag = xmlDocResponse.CreateDocumentFragment();
                xfrag.InnerXml = decryptedValue;
                xmlDocResponse.DocumentElement.AppendChild(xfrag);
            }
        }


        public bool IsStatusSuccess()
        {
            XmlNode node = GetNode("/samlp:Response/samlp:Status/samlp:StatusCode");
            if (node == null || node.Attributes["Value"] == null)
                return false;
            else
                return node.Attributes["Value"].Value.EndsWith("Success");
        }

        private bool DoesNeedToBeDecrypted()
        {
            XmlNode nodeEncryptedAssertion = GetNode("/samlp:Response/saml:EncryptedAssertion");
            XmlNode nodeAssertion = GetNode("/samlp:Response/saml:Assertion");

            return nodeAssertion == null && nodeEncryptedAssertion != null;
        }


        public virtual string GetNameID()
        {
            string nameID = string.Empty;

            XmlNode node = GetNode("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID");
            if (node != null)
                nameID = node.InnerText;

            if (nameID == string.Empty)
                throw new Exception("NameID is not found in the response");
            return nameID;
        }


        public virtual string GetSessionIndex()
        {
            string sessionIndex = string.Empty;

            XmlNode node = GetNode("/samlp:Response/saml:Assertion/saml:AuthnStatement");
            if (node != null && node.Attributes["SessionIndex"] != null)
                sessionIndex = node.Attributes["SessionIndex"].Value; 

            if (sessionIndex == string.Empty)
                throw new Exception("SessionIndex is not found in the response");
            return sessionIndex;
        }





        private byte[] GetCipherKey(XmlDocument xmlDocResponse, X509Certificate2 myCert)
        {
            XmlNode encryptedCipherValueNode = GetNode("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue");
            if (encryptedCipherValueNode == null)
                throw new Exception("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue node is not found");
            string encryptedCipher = encryptedCipherValueNode.InnerText;

            byte[] bytesEncryptedCipher = Convert.FromBase64String(encryptedCipher);
            RSACryptoServiceProvider csp = (RSACryptoServiceProvider)myCert.PrivateKey;

            byte[] bytesDecryptedCipher = csp.Decrypt(bytesEncryptedCipher, true);

            return bytesDecryptedCipher;
        }

        private XmlNode GetNode(string path)
        {
            XmlNamespaceManager manager = new XmlNamespaceManager(xmlDocResponse.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            manager.AddNamespace("xenc", "http://www.w3.org/2001/04/xmlenc#");

            XmlNode node = xmlDocResponse.SelectSingleNode(path, manager);
            return node;
        }

        public string ResponseString()
        {
            return xmlDocResponse == null ? "document == null" : xmlDocResponse.OuterXml;
        }

    }

}