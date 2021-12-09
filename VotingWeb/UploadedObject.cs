using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace VotingWeb
{
    public class UploadedObject
    {

        

        public string id { get; set; }

        

        public string content { get; set; }

      
        public UploadedObject(string id, string content)
        {
            this.id = id;
            this.content = content;
        }


    }
}