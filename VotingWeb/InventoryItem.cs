using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace VotingWeb
{
    public class InventoryItem
    {
        public InventoryItem(string id, string content)
        {
            Id = id;
            Content = content;
        }
        public string Id { get; set; }
        public string Content { get; set; }
    }
}
