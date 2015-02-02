using System;
using System.Configuration;

using Ensues.Security.Cryptography;
namespace Ensues.Configuration {
    internal class PasswordGeneratorElement : ConfigurationElement {
        [ConfigurationProperty("length", IsRequired = false, DefaultValue = 10)]
        public int Length {
            get { return (int)this["length"]; }
            set { this["length"] = value; }
        }

        [ConfigurationProperty("symbols", IsRequired = false, DefaultValue = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")]
        public string Symbols {
            get { return (string)this["symbols"]; }
            set { this["symbols"] = value; }
        }

        public void ConfigurePasswordGenerator(PasswordGenerator passwordGenerator) {
            if (null == passwordGenerator) throw new ArgumentNullException("passwordGenerator");
            passwordGenerator.Length = Length;
            passwordGenerator.Symbols = Symbols;
        }
    }
}
