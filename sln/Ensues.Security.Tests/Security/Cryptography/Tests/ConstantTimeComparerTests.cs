using System;
using System.Linq;

using NUnit.Framework;

namespace Ensues.Security.Cryptography.Tests {
    
    [TestFixture]
    public class ConstantTimeComparerTests {

        [Test]
        public void Equals_ReturnsTrueForEqualStrings() {
            var c = new ConstantTimeComparer();
            Assert.IsTrue(c.Equals(default(string), (string)null));
            Assert.IsTrue(c.Equals("", string.Empty));
            Assert.IsTrue(c.Equals("longer string", new string("longer string".Select(s => s).ToArray())));
        }

        [Test]
        public void Equals_ReturnsFalseForNonequalStrings() {
            var c = new ConstantTimeComparer();
            Assert.IsFalse(c.Equals(default(string), string.Empty));
            Assert.IsFalse(c.Equals("different case", "diFferent case"));
            Assert.IsFalse(c.Equals("different length", "different length "));
        }
    }
}
