using System.Collections.Generic;
using System.Linq;

namespace VotingWeb
{
    public class InventoryRepository : Dictionary<string, string>
    {
        public InventoryRepository()
        {
        }

        //public InventoryItem[] GetAllItems()
        //{
        //    return this.Select(x => new InventoryItem(x.Key, x.Value)).ToArray();
        //}

        public string GetContent(string id)
        {
            return this.GetValueOrDefault(id);
        }

        public void AddItem(string id, string content)
        {
            
            this.Add(id, content);
        }

        public void SetContent(string id, string content)
        {
            this[id] = content;
        }

        public void RemoveItem(string id)
        {
            this.Remove(id);
        }
    }
}