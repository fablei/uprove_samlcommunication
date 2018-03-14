using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace uprove_samlcommunication
{
    public class SamlMetadataController
    {
        #region Properties
        private string MetadataEnding = "metadata-{0}.xml";
        #endregion Properties

        #region ReadFile
        /// <summary>
        ///  Loads the xml metadata file from the defined metadataDirectory
        ///  the metadata files must have the name metadata-[issuername].xml
        /// </summary>
        /// <param name="issuerName">the name of the file</param>
        /// <param name="metadataDirectoryPath">defines the directory (folder) where the metadata files are</param>
        /// <param name="trim">If the spaces should be eliminated or not</param>
        /// <returns>the content of the file</returns>
        public string ReadFile(string issuerName, string metadataDirectoryPath, bool trim = false)
        {
            LogService.Log(LogService.LogType.Info, "SamlMetadataController - ReadFile called");
            string filePath = metadataDirectoryPath + MetadataEnding;
            string[] files = File.ReadAllLines(String.Format(filePath, issuerName), Encoding.UTF8);
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < files.Length; i++)
            {
                if (trim)
                    sb.AppendLine(Regex.Replace(files[i].ToString().Trim().Replace(Environment.NewLine, String.Empty), @"\r\n?|\n", String.Empty));
                else
                    sb.AppendLine(files[i].ToString());
            }

            LogService.Log(LogService.LogType.Info, "metadata file found and returned");
            return sb.ToString();
        }
        #endregion ReadFile
    }
}
