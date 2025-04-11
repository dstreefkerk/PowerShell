# Markdown to Word Converter Test Document

This document contains various markdown elements to test the conversion functionality, with special focus on headings and bullet point lists at different nesting levels.

## Heading Level 2

This is a paragraph under a level 2 heading. The text should maintain proper formatting when converted to Word.

### Heading Level 3

Level 3 headings should use a smaller font size than level 2 headings in the final Word document.

#### Heading Level 4
Level 4 headings are even smaller.

##### Heading Level 5
And level 5 is smaller still.

###### Heading Level 6
Level 6 is the smallest heading level in markdown.

## Basic Text Formatting

You can make text **bold** or *italic* or ***both bold and italic***. You can also add ~~strikethrough~~ to text.

## Simple Bullet List

* First item
* Second item
* Third item
* Fourth item

## Numbered List

1. First numbered item
2. Second numbered item
3. Third numbered item
4. Fourth numbered item

## Nested Bullet Lists (Testing Level Styling)

* Level 1 item
  * Level 2 item
  * Another level 2 item
    * Level 3 item
    * Another level 3 item
      * Level 4 item
        * Level 5 item
          * Level 6 item
            * Level 7 item
              * Level 8 item
                * Level 9 item
* Back to level 1
  * Level 2 again
    * Level 3 again

## Mixed List Types

* Bullet item 1
  1. Numbered sub-item 1
  2. Numbered sub-item 2
* Bullet item 2
  * Bullet sub-item
    1. Nested numbered item
    2. Another nested numbered item

## Links and References

[This is a link to Pandoc's website](https://pandoc.org/)

## Blockquotes

> This is a blockquote. It should be styled differently in the Word document.
>
> Multiple paragraphs in a blockquote should be maintained.
>
> > Nested blockquotes should also be preserved and styled appropriately.

## Code Blocks

Inline code like `function helloWorld()` should be preserved.

```powershell
# This is a PowerShell code block
function Test-MarkdownConverter {
    param(
        [string]$InputFile,
        [string]$OutputFile
    )
    
    Write-Output "Converting $InputFile to $OutputFile"
}
```

## Tables

| Header 1 | Header 2 | Header 3 |
|----------|----------|----------|
| Row 1, Col 1 | Row 1, Col 2 | Row 1, Col 3 |
| Row 2, Col 1 | Row 2, Col 2 | Row 2, Col 3 |
| Row 3, Col 1 | Row 3, Col 2 | Row 3, Col 3 |

## Horizontal Rule

The following is a horizontal rule:

---

## Combined Elements with Lists

### Scenario 1: Lists with formatted text

* This item has **bold text** within it
* This item has *italic text* within it
* This item has a `code snippet` within it
* This item has [a link](https://example.com) within it

### Scenario 2: Complex nesting with mixed formatting

* Main bullet point
  * Sub-bullet with **bold text**
    * Sub-sub-bullet with *italic text*
      * Deep nested bullet with ***bold and italic text***
        * Even deeper with ~~strikethrough~~
          * And deeper still with `code`
            * With a [link](https://example.com) at the deepest level

## Alternative Markdown Syntax

- This is a bullet point using dash instead of asterisk
  - This is a nested bullet using dash
    - This is a deeper nested bullet using dash

+ This is a bullet point using plus sign
  + This is a nested bullet using plus sign
    + This is a deeper nested bullet using plus sign

## Final Notes

This document should test most common markdown elements with focus on bullet list styling at various levels. The enhanced Lua filter in the converter should apply the appropriate "List Bullet" styles to each nesting level (up to 9 levels deep as supported by Word).
