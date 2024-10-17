using DotNetNuke.Instrumentation;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Xsl;

namespace DotNetNuke.Authentication.SAML
{
    public static class StaticHelper
    {
        public static X509Certificate2 LoadCertificateFromPEM(string certPem, string keyPem)
        {
            string sanitizedCert = SanitizePem(certPem, "CERTIFICATE");
            string sanitizedKey = keyPem; // SanitizePem(keyPem, "PRIVATE KEY");


            byte[] certBytes = Convert.FromBase64String(sanitizedCert);

            AsymmetricKeyParameter keyParameter;
            using (var sr = new StringReader(sanitizedKey))
            {
                var pemReader = new PemReader(sr);
                keyParameter = (AsymmetricKeyParameter)pemReader.ReadObject();
            }

            RSA rsaKey = DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)keyParameter);
            var certificate = new X509Certificate2(certBytes);
            certificate = certificate.CopyWithPrivateKey(rsaKey);

            return certificate;
        }

        private static string SanitizePem(string pem, string section)
        {
            StringBuilder sb = new StringBuilder(pem);
            sb.Replace($"-----BEGIN {section}-----", string.Empty);
            sb.Replace($"-----END {section}-----", string.Empty);
            sb.Replace("\n", string.Empty);
            sb.Replace("\r", string.Empty);
            return sb.ToString();
        }

        internal static AsymmetricKeyParameter GetPrivateKeyFromPem(string key)
        {
            using (var reader = new StringReader(key))
            {
                var pemReader = new PemReader(reader);
                var keyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                return keyPair.Private;
            }
        }

        internal static string SignSAMLRequest(string samlRequest, AsymmetricKeyParameter privateKey)
        {
            var encoding = new UTF8Encoding();
            var data = encoding.GetBytes(samlRequest);

            ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");
            signer.Init(true, privateKey);
            signer.BlockUpdate(data, 0, data.Length);
            var signedData = signer.GenerateSignature();

            var base64SignedData = Convert.ToBase64String(signedData);
            return $"<ds:SignatureValue>{base64SignedData}</ds:SignatureValue>{samlRequest}";
        }

        public static X509Certificate2 GetCert(string friendlyName)
        {
            //http://stackoverflow.com/questions/23394654/signing-a-xml-document-with-x509-certificate
            string s = string.Empty;

            X509Certificate2 myCert = new X509Certificate2("", "");
            //var store = new X509Store(StoreLocation.LocalMachine);
            //store.Open(OpenFlags.ReadOnly);
            //var certificates = store.Certificates;
            ////LogToEventLog("DNN.Authentication.SAML.FindCert()", string.Format("Found {0} certs", certificates.Count));
            //foreach (var certificate in certificates)
            //{
            //    s += string.Format("cert subj : {0}, friendly name : {1}; ", certificate.Subject, certificate.FriendlyName);
            //    if (certificate.FriendlyName.ToLower().Contains(friendlyName.ToLower()))
            //    {
            //        myCert = certificate;
            //    }
            //}

            ////LogToEventLog("DNN.Authentication.SAML.FindCert()", string.Format("certs info : {0}", s));
            //if (myCert == null)
            //    throw new Exception("x509 Certificate with " + friendlyName + " in its friendly name was not found");

            return myCert;
        }

        public static XmlDocument SignSAMLRequest(XmlDocument xmlDoc, X509Certificate2 myCert)
        {
            XmlElement xmlDigitalSignature = CreateXMLSignature(xmlDoc, myCert);
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
            return xmlDoc;
        }

        public static XmlDocument SignSAMLRequest2(XmlDocument xmlDoc, X509Certificate2 myCert)
        {
            XmlElement xmlDigitalSignature = CreateXMLSignature(xmlDoc, myCert);
            
            xmlDoc.DocumentElement.InsertAfter(xmlDoc.ImportNode(xmlDigitalSignature, true), xmlDoc.DocumentElement.FirstChild);
            return xmlDoc;
        }

        public static XmlElement CreateXMLSignature(XmlDocument xmlDoc, X509Certificate2 myCert)
        {
            if (!myCert.HasPrivateKey)
            {
                throw new SignatureException("Certificate does not have a private key");
            }
            //https://msdn.microsoft.com/en-us/library/ms229745(v=vs.110).aspx
            //RSACryptoServiceProvider rsaKey = (RSACryptoServiceProvider)myCert.GetRSAPrivateKey();
            SignedXml signedXml = new SignedXml(xmlDoc);
            signedXml.SigningKey = myCert.GetRSAPrivateKey();
            Reference reference = new Reference();
            reference.Uri = "#" + xmlDoc.FirstChild.Attributes["ID"].Value;
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            //add KeyInfo clause -  https://msdn.microsoft.com/en-us/library/ms148731(v=vs.110).aspx ---------
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(myCert));
            signedXml.KeyInfo = keyInfo;
            //--------------------------------------------------------------------------------------------------
            signedXml.ComputeSignature();
            XmlElement xmlDigitalSignature = signedXml.GetXml();
            return xmlDigitalSignature;
        }

        public static byte[] SignString(string text, X509Certificate2 myCert)
        {
            //http://blogs.msdn.com/b/alejacma/archive/2008/06/25/how-to-sign-and-verify-the-signature-with-net-and-a-certificate-c.aspx

            // Hash the data
            SHA1Managed sha1 = new SHA1Managed();
            UnicodeEncoding encoding = new UnicodeEncoding();
            //UTF8Encoding encoding = new UTF8Encoding();
            byte[] data = encoding.GetBytes(text);
            byte[] hash = sha1.ComputeHash(data);

            // Sign the hash
            RSACryptoServiceProvider rsaKey = (RSACryptoServiceProvider)myCert.PrivateKey;
            byte[] signedBytes = rsaKey.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));
            return signedBytes;
        }

        public static byte[] SignString3(string text, X509Certificate2 cert)
        {
            RSACryptoServiceProvider key = new RSACryptoServiceProvider();
            key.FromXmlString(cert.PrivateKey.ToXmlString(true));
            UnicodeEncoding encoding = new UnicodeEncoding();
            byte[] data = encoding.GetBytes(text);

            //Sign the data
            byte[] sig = key.SignData(data, CryptoConfig.MapNameToOID("SHA1"));
            return sig;
        }

        public static byte[] SignString2(string text, string pemKey)
        {
            //http://stackoverflow.com/questions/3240222/get-private-key-from-bouncycastle-x509-certificate-c-sharp
            AsymmetricKeyParameter bouncyCastlePrivateKey = TransformRSAPrivateKey(pemKey);

            //http://stackoverflow.com/questions/8830510/c-sharp-sign-data-with-rsa-using-bouncycastle
            ISigner sig = SignerUtilities.GetSigner("SHA256withRSA");
            sig.Init(true, bouncyCastlePrivateKey);
            var data = Encoding.UTF8.GetBytes(text);
            sig.BlockUpdate(data, 0, data.Length);
            return sig.GenerateSignature();
        }

        public static AsymmetricKeyParameter TransformRSAPrivateKey(string pemKey)
        {
            RSACryptoServiceProvider prov = RSAKeys.ImportPrivateKey(pemKey); // privateKey as RSACryptoServiceProvider;
            RSAParameters parameters = prov.ExportParameters(true);

            return new RsaPrivateCrtKeyParameters(
                new BigInteger(1, parameters.Modulus),
                new BigInteger(1, parameters.Exponent),
                new BigInteger(1, parameters.D),
                new BigInteger(1, parameters.P),
                new BigInteger(1, parameters.Q),
                new BigInteger(1, parameters.DP),
                new BigInteger(1, parameters.DQ),
                new BigInteger(1, parameters.InverseQ));
        }



        internal static string Base64UrlEncode(string xml)
        {
            return HttpUtility.UrlEncode(Convert.ToBase64String(Encoding.UTF8.GetBytes(xml)));
        }

        public static string Base64CompressUrlEncode(string xml)
        {
            //http://stackoverflow.com/questions/12090403/how-do-i-correctly-prepare-an-http-redirect-binding-saml-request-using-c-sharp
            string base64 = string.Empty;
            var bytes = Encoding.UTF8.GetBytes(xml);
            using (var output = new MemoryStream())
            {
                using (var zip = new System.IO.Compression.DeflateStream(output, System.IO.Compression.CompressionMode.Compress))
                {
                    zip.Write(bytes, 0, bytes.Length);
                }
                base64 = Convert.ToBase64String(output.ToArray());
            }
            return HttpUtility.UrlEncode(base64);
        }

        public static string Base64CompressUrlEncode(XmlDocument doc)
        {
            string xml = doc.OuterXml;
            return Base64CompressUrlEncode(xml);
        }

        public static byte[] StringToByteArray(string st)
        {
            return Convert.FromBase64String(st);
        }

        public static string ByteArrayToString(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }
        public static string GetFirstName(string displayName)
        {
            return displayName.Split(' ')
                .First();
        }

        public static string GetLastName(string displayName)
        {
            return displayName.Split(' ')
                .Skip(1)
                .Aggregate("", (current, next) => current + " " + next)
                .TrimStart(' ');
        }
        public static void EnsureNotEmpty(string propertyName, string propertyValue, ILog logger, string correlationId)
        {
            if (string.IsNullOrEmpty(propertyValue))
            {
                throw new ApplicationException($"{propertyName} is null or empty");
            }
            logger.Info($"CorrelationId={correlationId}. {propertyName} is: {propertyValue}");
        }
    }

}