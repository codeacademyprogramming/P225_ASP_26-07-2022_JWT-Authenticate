using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace P225FirstApi.DTOs.CategoryDTOs
{
    public class CategoryGetDto
    {
        public int Id { get; set; }
        public string Ad { get; set; }
        public bool Esasdirmi { get; set; }
        public string Sekil { get; set; }
        public Nullable<int> AidOlduguKategoriyaninIdsi { get; set; }
    }
}
