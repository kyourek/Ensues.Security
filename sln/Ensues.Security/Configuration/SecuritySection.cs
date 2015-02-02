using System;
using System.Configuration;

using Ensues.Security.Cryptography;
namespace Ensues.Configuration {    
    internal class SecuritySection : ConfigurationSection {
        [ConfigurationProperty("passwordAlgorithm", IsRequired = false, DefaultValue = null)]
        public PasswordAlgorithmElement PasswordAlgorithm {
            get { return (PasswordAlgorithmElement)this["passwordAlgorithm"]; }
            set { this["passwordAlgorithm"] = value; }
        }

        public void ConfigurePasswordAlgorithm(PasswordAlgorithm passwordAlgorithm) {
            var element = PasswordAlgorithm;
            if (element != null) {
                var elementInformation = element.ElementInformation;
                if (elementInformation != null && elementInformation.IsPresent) {
                    element.ConfigurePasswordAlgorithm(passwordAlgorithm);
                }
            }
        }
    }
}
