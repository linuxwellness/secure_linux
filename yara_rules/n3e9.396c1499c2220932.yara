
rule n3e9_396c1499c2220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.396c1499c2220932"
     cluster="n3e9.396c1499c2220932"
     cluster_size="44"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lethic strictor orbus"
     md5_hashes="['23dad9920fd2d067341d90fd756919d2','2dea84c11625e853a6787ef6e36ad02e','aa9dd74c1a565546fc08684bde5db314']"

   strings:
      $hex_string = { 3f003000008800000010301f302c3036304d305730673071308b309230a230ad30c630cd30de30e5300331133122312c3143314d315c31693176318c31a231ac }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
