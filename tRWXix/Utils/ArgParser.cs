using System.Collections.Generic;

namespace tRWXix.Utils
{
    internal class ArgParser
    {
        internal static Dictionary<string, string> parse(string[] args)
        {
            Dictionary<string, string> res = new Dictionary<string, string>();
            foreach (var arg in args)
            {
                string[] split = arg.Split('=');
                var r = split[0].Replace("/", string.Empty);
                if (split.Length == 1)
                {
                    res[r] = "true";
                }
                if (split.Length == 2)
                {
                    res[r] = split[1];
                }
            }
            return res;
        }
    }
}
