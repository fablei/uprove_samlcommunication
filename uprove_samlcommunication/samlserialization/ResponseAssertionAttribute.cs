using Newtonsoft.Json;

namespace uprove_samlcommunication.samlserialization
{
    public class ResponseAssertionAttribute
    {
        public string Key { get; set; }

        public string NameFormat { get; set; }

        public string[] Values { get; set; }

        public bool IsChecked { get; set; }

        public bool IsMandatory { get; set; }

        public int AttributeQualityLevel { get; set; }

        public string ValuesToString()
        {
            string values = "";

            if(Values != null && Values.Length > 0)
                foreach (string v in Values)
                {
                    if (values != "")
                        values += ", " + v.ToString();
                    else
                        values = v.ToString();
                }

            return values;
        }

        public string ParseToJson()
        {
            JsonSerializerSettings settings = new JsonSerializerSettings();
            settings.NullValueHandling = NullValueHandling.Ignore;

            return JsonConvert.SerializeObject(this, settings);
        }
    }
}