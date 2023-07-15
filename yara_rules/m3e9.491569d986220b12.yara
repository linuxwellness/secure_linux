
rule m3e9_491569d986220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.491569d986220b12"
     cluster="m3e9.491569d986220b12"
     cluster_size="27"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bamital ramnit malicious"
     md5_hashes="['01060c809c78ec070068d8947b513a9b','02bbe5cf49321b74b79600769d9c070b','99b57a94c8b973b88dce2af82c6b5f82']"

   strings:
      $hex_string = { b5111b8a602b34e93620babe1ee8210eeeabac4fe68b4e02e71024944b9bcf480d1ca6e33a6e68970b637d04ab12166d8de5f6a5ea6b6a9a2a40504125d047fc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
