
rule o26c0_4914ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.4914ea48c0000b12"
     cluster="o26c0.4914ea48c0000b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious heuristic amlioos"
     md5_hashes="['30bf12ded205c2155169de4b37e2087e74126896','5e20476f4601e4b68bdbf6de7c307b906485b9ef','5a6996b9dd0b0d87fc10b6695b5e754e38c2f3a4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.4914ea48c0000b12"

   strings:
      $hex_string = { 8d46185750e88ec8ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
