# Revit C# Add-in Quick Reference

## Project Setup

### .csproj (targeting Revit 2024)
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net48</TargetFramework>
    <CopyLocal>false</CopyLocal>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Revit_All_Main_Versions_API_x64" Version="2024.*" />
  </ItemGroup>
</Project>
```

### .addin manifest
```xml
<?xml version="1.0" encoding="utf-8"?>
<RevitAddIns>
  <AddIn Type="Command">
    <Name>MyCommand</Name>
    <Assembly>path\to\MyAddin.dll</Assembly>
    <ClientId>11111111-2222-3333-4444-555555555555</ClientId>
    <FullClassName>MyAddin.Command</FullClassName>
    <VendorId>YOURID</VendorId>
  </AddIn>
</RevitAddIns>
```
Place in: `%APPDATA%\Autodesk\Revit\Addins\2024\`

## Object Detection

### FilteredElementCollector — the workhorse

```csharp
using Autodesk.Revit.DB;
using Autodesk.Revit.UI;

// Get all elements of a category
var walls = new FilteredElementCollector(doc)
    .OfCategory(BuiltInCategory.OST_Walls)
    .WhereElementIsNotElementType()
    .ToElements();

// By class type
var beams = new FilteredElementCollector(doc)
    .OfClass(typeof(FamilyInstance))
    .OfCategory(BuiltInCategory.OST_StructuralFraming)
    .ToElements();

// By parameter value
var fireRated = new FilteredElementCollector(doc)
    .OfCategory(BuiltInCategory.OST_Walls)
    .WhereElementIsNotElementType()
    .Where(e => e.get_Parameter(BuiltInParameter.WALL_ATTR_FIRE_RATING)
                    ?.AsInteger() > 0)
    .ToList();

// Built-in logical filters
var filtered = new FilteredElementCollector(doc)
    .OfCategory(BuiltInCategory.OST_Walls)
    .WhereElementIsElementType()
    .ToList();
```

### ElementParameterFilter — fast parameter queries

```csharp
// Find walls with "Fire Rating" = "2 Hours"
var rule = ParameterFilterRuleFactory.CreateEqualsRule(
    new ElementId(BuiltInParameter.WALL_ATTR_FIRE_RATING),
    2);

var filter = new ElementParameterFilter(rule);
var walls = new FilteredElementCollector(doc)
    .OfCategory(BuiltInCategory.OST_Walls)
    .WherePasses(filter)
    .ToList();
```

## Making Changes

### Parameter modification (requires transaction)

```csharp
using (Transaction t = new Transaction(doc, "Update comment"))
{
    t.Start();
    foreach (var wall in walls)
    {
        var comment = wall.get_Parameter(BuiltInParameter.ALL_MODEL_INSTANCE_COMMENTS);
        if (comment != null && !comment.IsReadOnly)
        {
            comment.Set("Updated by script");
        }
    }
    t.Commit();
}
```

### Move/copy elements

```csharp
using (Transaction t = new Transaction(doc, "Move"))
{
    t.Start();
    ElementTransformUtils.MoveElement(doc, element.Id, XYZ.BasisZ * 10);
    t.Commit();
}
```

### Delete elements

```csharp
ICollection<ElementId> ids = walls.Select(w => w.Id).ToList();
using (Transaction t = new Transaction(doc, "Delete"))
{
    t.Start();
    doc.Delete(ids);
    t.Commit();
}
```

## Common Patterns

### Find by name/pattern

```csharp
var targetWalls = new FilteredElementCollector(doc)
    .OfClass(typeof(Wall))
    .Cast<Wall>()
    .Where(w => w.Name.Contains("Exterior"))
    .ToList();
```

### Check if parameter exists

```csharp
Parameter param = element.LookupParameter("MyCustomParam");
if (param != null && param.HasValue && !param.IsReadOnly)
{
    param.Set(newValue);
}
```

### Get built-in parameter safely

```csharp
string GetParamOrDefault(Element e, BuiltInParameter bip, string fallback = "")
{
    var p = e.get_Parameter(bip);
    return p?.AsValueString()
        ?? p?.AsString()
        ?? fallback;
}
```

## Macros (alternative to add-ins)

- Open: Manage → Macros → Macro Manager
- Creates a .cs file in the Revit app data folder
- No .addin manifest needed
- Same API, less boilerplate

```csharp
public void DetectAndTagWalls()
{
    var doc = this.ActiveUIDocument.Document;
    var walls = new FilteredElementCollector(doc)
        .OfCategory(BuiltInCategory.OST_Walls)
        .WhereElementIsNotElementType()
        .ToElements();

    using (Transaction t = new Transaction(doc, "Tag"))
    {
        t.Start();
        TaskDialog.Show("Found", $"{walls.Count} walls found");
        // modify walls here
        t.Commit();
    }
}
```

## Key Facts

- **Framework:** .NET Framework 4.8 (not .NET Core/5+)
- **Threading:** Single-threaded — all API calls must be on main thread
- **External events:** Use `IExternalEventHandler` for async work
- **Transactions:** Any document change requires a transaction
- **Units:** Internal units are feet. Convert via `UnitUtils.Convert()`
- **Python alternative:** pyRevit — fast iteration, same API via IronPython
