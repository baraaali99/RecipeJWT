namespace Api.Models
{
    public class Recipe
    {
        public string Title { get; set; }
        public Guid Id { get; set; }
        public List<string> Ingredients { get; set; } = new List<string>();
        public List<string> Instructions { get; set; } = new List<string>();
        public List<string> Categories { get; set; } = new List<string>();
        public Recipe(string title, List<string> ingredients, List<string> instructions, List<string> categories, Guid id)
        {
            Title = title;
            Ingredients = ingredients;
            Instructions = instructions;
            Categories = categories;
            Id = id;
        }

        public Recipe()
        {
            Title = "";
            Instructions = new List<string>();
            Categories = new List<string>();
            Ingredients = new List<string>();
            Id = Guid.NewGuid();
        }
    }
}
