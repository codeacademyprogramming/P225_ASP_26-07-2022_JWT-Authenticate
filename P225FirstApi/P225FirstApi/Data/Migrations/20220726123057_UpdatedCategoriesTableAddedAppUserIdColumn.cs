using Microsoft.EntityFrameworkCore.Migrations;

namespace P225FirstApi.Data.Migrations
{
    public partial class UpdatedCategoriesTableAddedAppUserIdColumn : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AppUserId",
                table: "Categories",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Categories_AppUserId",
                table: "Categories",
                column: "AppUserId");

            migrationBuilder.AddForeignKey(
                name: "FK_Categories_AspNetUsers_AppUserId",
                table: "Categories",
                column: "AppUserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Categories_AspNetUsers_AppUserId",
                table: "Categories");

            migrationBuilder.DropIndex(
                name: "IX_Categories_AppUserId",
                table: "Categories");

            migrationBuilder.DropColumn(
                name: "AppUserId",
                table: "Categories");
        }
    }
}
