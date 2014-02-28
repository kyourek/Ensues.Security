using System;
using System.Collections.Generic;
using System.Linq;

namespace Ensues.Security.Cryptography {

    internal class ConstantTimeComparer : IEqualityComparer<string> {

        private static string Extend(string s, int count) {
            return s + new string(Enumerable.Range(0, count).Select(_ => '_').ToArray());
        }

        public virtual bool Equals(string x, string y) {
            var s1 = x ?? string.Empty;
            var s2 = y ?? string.Empty;

            var s1len = s1.Length;
            var s2len = s2.Length;

            if (s1len < s2len) {
                s1 = Extend(s1, s2len - s1len);
            }

            if (s2len < s1len) {
                s2 = Extend(s2, s1len - s2len);
            }

            var diff = (uint)0;
            var slen = s1.Length;
            for (var i = 0; i < slen; i++) {

                diff |= (uint)(s1[i] ^ s2[i]);
            }

            return x == null || y == null
                ? x == null && y == null
                : s1len == s2len && diff == 0;
        }

        public virtual int GetHashCode(string obj) {
            throw new NotImplementedException();
        }
    }
}
