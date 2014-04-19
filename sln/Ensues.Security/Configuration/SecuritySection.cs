using System;
using System.Configuration;

namespace Ensues.Configuration {
    
    internal class SecuritySection : ConfigurationSection {

        [ConfigurationProperty("passwordAlgorithm", IsRequired = false, DefaultValue = null)]
        public PasswordAlgorithmElement PasswordAlgorithm {
            get { return (PasswordAlgorithmElement)this["passwordAlgorithm"]; }
            set { this["passwordAlgorithm"] = value; }
        }
    }
}
