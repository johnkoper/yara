/*
  Comment
*/

rule BasicRule
{
  strings:
    $test_string= "basic"
  condition:
    $test_string
}

rule AnotherRule : Family {
  meta:
    description = "descr"
    author = "John Koper"
    last_updated = "2025-12-06"
  
  strings:
    $m1 = "\x00\x00ERXXXXXXX\x00\x00" wide
    $m2 = "\x00\x00ER\x00\x00" wide // inline comment

  condition:
    any of them

}
