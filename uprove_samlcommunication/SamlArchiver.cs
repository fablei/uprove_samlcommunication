using System.Collections.Generic;

namespace uprove_samlcommunication
{
    public class SamlArchiver
    {
        #region Properties
        private Dictionary<string, string> archive = new Dictionary<string, string>();
        #endregion Properties

        #region Exists
        /// <summary>
        /// Checks if the given key exists or not
        /// </summary>
        /// <param name="key">looking for this key</param>
        /// <returns>true->exists, false->does not exist</returns>
        public bool Exists(string key)
        {
            LogService.Log(LogService.LogType.Info, "SamlArchiver check if key: '" + key + "' exists.");
            return archive.ContainsKey(key);
        }
        #endregion Exists

        #region GetArchivedObject
        /// <summary>
        /// Reads the value to the given key -> if object with this key exists
        /// </summary>
        /// <param name="key">searching key</param>
        /// <returns>if key exists->object, if not->exception</returns>
        public string GetArchivedObject(string key)
        {
            LogService.Log(LogService.LogType.Info, "SamlArchiver - GetArchivedObject with key: '" + key + "' called");
            if (!Exists(key))
                throw new SamlCommunicationException("Key does not exists, " + key, SamlCommunicationType.SAMLARCHIVE);

            // get value
            string value = archive[key];
            // delete key/value-pair
            if (!archive.Remove(key))
                throw new SamlCommunicationException("Error while removing key, " + key, SamlCommunicationType.SAMLARCHIVE);

            LogService.Log(LogService.LogType.Info, "Object found (removed) and returned");
            return value;
        }
        #endregion GetArchivedObject

        #region SetObjectToArchive
        /// <summary>
        /// Sets a key value pair to the archiver
        /// </summary>
        /// <param name="key">under this key the object will be found</param>
        /// <param name="value">value/object which is saved under the given key</param>
        /// <returns>true->saving was successful, false/exception->something went wrong</returns>
        public bool SetObjectToArchive(string key, string value)
        {
            LogService.Log(LogService.LogType.Info, "SamlArchiver - SetObjectToArchive with key: '" + key + "' called");
            if (Exists(key))
                throw new SamlCommunicationException("Key already exists, " + key, SamlCommunicationType.SAMLARCHIVE);

            archive.Add(key, value);
            LogService.Log(LogService.LogType.Info, "Object successfully added to the archiver.");

            return Exists(key);
        }
        #endregion SetObjectToArchive
    }
}