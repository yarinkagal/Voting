using System.Collections.Generic;
using System.Net;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace VotingWeb.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    public class InventoryController : Controller
    {
        public TraceLog traceLog;
        private InventoryRepository inventory;
        TrafficManager manager;

        public InventoryController(TraceLog traceLog, InventoryRepository inventoryRepository)
        {
            this.traceLog = traceLog;
            this.inventory = inventoryRepository;

        }

        [HttpGet]
        public ActionResult<IEnumerable<InventoryItem>> Get()
        {
            if (manager == null)
                manager = new TrafficManager();
            var result = this.manager.GetAllData();
            //var result = this.inventory.GetAllItems();

            this.traceLog.LogInfo("Inventory.GetAll", $"Getting array of {result.Length} items");
            return result;
        }

        [HttpGet("{id}")]
        public ActionResult<InventoryItem> Get(string id)
        {
            var content = this.inventory.GetContent(id);
            
            //return content;

            if (manager == null)
                manager = new TrafficManager();
            this.traceLog.LogInfo("Inventory.Get", $"Getting Id='{id}', Content={content}");
            return manager.GetOneData(id);
        }

        [HttpPost("{Id}")]
        public  InventoryItem Post(string Id, [FromBody] string content)
        {
            if (manager == null)
                manager = new TrafficManager();
            InventoryItem inventoryItem = new InventoryItem(Id, content);
            manager.sendToEH(Id, inventoryItem);
            
            this.traceLog.LogInfo("Inventory.Add", $"Adding Id='{inventoryItem.Id}', Content={inventoryItem.Content}");
            this.inventory.AddItem(inventoryItem.Id, inventoryItem.Content);


            return inventoryItem;
        }

        [HttpPut("{id}")]
        public ActionResult Put(string Id, [FromBody] string newContent)
        {
            try
            {
                var originalContent = this.inventory.GetContent(Id);
                this.inventory.SetContent(Id, newContent);
                this.traceLog.LogInfo("Inventory.Update", $"Updating Id='{Id}' from {originalContent} to {newContent}");
                InventoryItem inventoryItem = new InventoryItem(Id, originalContent);
                manager.sendToEH(Id, inventoryItem);

                return Ok();
            }
            catch (InvalidContentException)
            {
                var message = $"Cannot update content of item '{Id}' to invalid value {newContent}";
                this.traceLog.LogInfo("Inventory.Update", message);
                return StatusCode((int)HttpStatusCode.InternalServerError, message);
            }
        }

        [HttpDelete("{id}")]
        public ActionResult Delete(string Id)
        {
            if (manager == null)
                manager = new TrafficManager();

            this.traceLog.LogInfo("Inventory.Delete", $"Deleting Id='{Id}'");
            this.inventory.RemoveItem(Id);
            manager.sendToEH(Id, null);
            return Ok();
        }
    }
}