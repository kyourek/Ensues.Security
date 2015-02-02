using System;
using System.Configuration;

using Ensues.Security.Cryptography;
namespace Ensues.Configuration {    
    internal class PasswordAlgorithmElement : ConfigurationElement {
        [ConfigurationProperty("compareInConstantTime", IsRequired = false, DefaultValue = true)]
        public bool CompareInConstantTime {
            get { return (bool)this["compareInConstantTime"]; }
            set { this["compareInConstantTime"] = value; }
        }

        [ConfigurationProperty("hashFunction", IsRequired = false, DefaultValue = HashFunction.SHA256)]
        public HashFunction HashFunction {
            get { return (HashFunction)this["hashFunction"]; }
            set { this["hashFunction"] = value; }
        }

        [ConfigurationProperty("saltLength", IsRequired = false, DefaultValue = 16)]
        public Int16 SaltLength {
            get { return (Int16)this["saltLength"]; }
            set { this["saltLength"] = value; }
        }

        [ConfigurationProperty("hashIterations", IsRequired = false, DefaultValue = 1000)]
        public Int32 HashIterations {
            get { return (Int32)this["hashIterations"]; }
            set { this["hashIterations"] = value; }
        }

        public void ConfigurePasswordAlgorithm(PasswordAlgorithm passwordAlgorithm) {
            if (null == passwordAlgorithm) throw new ArgumentNullException("passwordAlgorithm");
            passwordAlgorithm.CompareInConstantTime = CompareInConstantTime;
            passwordAlgorithm.HashFunction = HashFunction;
            passwordAlgorithm.HashIterations = HashIterations;
            passwordAlgorithm.SaltLength = SaltLength;
        }
    }
}
