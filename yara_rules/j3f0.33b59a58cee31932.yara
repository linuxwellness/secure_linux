
rule j3f0_33b59a58cee31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.33b59a58cee31932"
     cluster="j3f0.33b59a58cee31932"
     cluster_size="28"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious malob patched"
     md5_hashes="['022e7543526ed3ecc986b8bd2881dabb','190baf9048ca711e7448b7cfa70455e6','8f45532b35b72f81fa3cbde23f63ce97']"

   strings:
      $hex_string = { 721d8b3989382bf203c203ca3bf273f285f674148a11881040414e75f7eb098a11881040414e75f70fb6314183fe1073570fb611c1ea02c1e6068db432010700 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
