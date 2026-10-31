//! Tests for the ML-KEM-768 wrappers and the tunnel PSK derivation.
//!
//! Known-answer vectors: RustCrypto/KEMs, tag `ml-kem/v0.3.2`,
//! `ml-kem/tests/key-gen.json` and `ml-kem/tests/encap-decap.json` — the
//! ACVP-style vectors the `ml-kem` crate's own suite runs against.
//! Golden PSK vector: plan section 4.5
//! (`charter/design/rustynet-d3-seams-plan-v0.4.md`), as amended on
//! 2026-09-25: the info label is "rustynet-tunnel-psk-v1", because the
//! backend-boundary gate keeps transport names out of this crate. It was
//! independently re-derived with Python's hashlib/hmac before landing.

use super::*;

const GOLDEN_PSK_HEX: &str = "e8d59b87bd85c5a356a430659f2687a6839afa955975ca2ad0ff2547e69d4bad";

const GOLDEN_INFO_HEX: &str =
    "72757374796e65742d74756e6e656c2d70736b2d7631000a6e6f64652d616c70686100096e6f64652d6265746101";

const KAT_KEYGEN_D_26_HEX: &str =
    "e34a701c4c87582f42264ee422d3c684d97611f2523efe0c998af05056d693dc";

const KAT_KEYGEN_Z_26_HEX: &str =
    "a85768f3486bd32a01bf9a8f21ea938e648eae4e5448c34c3eb88820b159eedd";

const KAT_KEYGEN_EK_26_HEX: &str = "6d14a071f7cc452558d5e71a7b087062ecb1386844588246126402b1fa1637733cd5f60cc84bcb646a7892614d7c51b1c7f1a2799132f13427dc482158da254470a59e00a4e49686fdc077559367270c2153f11007592c9c4310cf8a12c6a8713bd6bb51f3124f989ba0d54073cc242e0968780b875a869efb851586b9a868a384b9e6821b201b932c455369a739ec22569c977c212b381871813656af5b567ef893b584624c863a259000f17b254b98b185097c50ebb68b244342e05d4de520125b8e1033b1436093ace7ce8e71b458d525673363045a3b3eea9455428a398705a42327adb3774b7057f42b017ec0739a983f19e8214d09195fa24d2d571db73c19a6f8460e50830d415f627b88e94a7b153791a0c0c7e9484c74d53c714889f0e321b6660a532a5bc0e557fbca35e29bc611200ed3c633077a4d873c5cc67006b753bf6d6b7af6ca402ab618236c0affbc801f8222fbc36ce0984e2b18c944bbcbef03b1e1361c1f44b0d734afb1566cff8744da8b9943d6b45a3c09030702ca201ffe20cb7ec5b0d4149ee2c28e8b23374f471b57150d0ec9336261a2d5cb84a3acacc4289473a4c0abc617c9abc178734434c82e1685588a5c2ea2678f6b3c2228733130c466e5b86ef491153e48662247b875d201020b566b81b64d839ab4633baa8ace202baab4496297f9807adbbb1e332c6f8022b2a18cfdd4a82530b6d3f007c3353898d966cc2c21cb4244bd00443f209870acc42bc33068c724ec17223619c1093cca6aeb29500664d1225036b4b81091906969481f1c723c140b9d6c168f5b64bea69c5fd6385df7364b8723bcc85e038c7e464a900d68a2127818994217aec8bdb39a970a9963de93688e2ac82abcc22fb9277ba22009e878381a38163901c7d4c85019538d35caae9c41af8c929ee20bb08ca619e72c2f2262c1c9938572551ac02dc9268fbcc35d79011c3c090ad40a4f111c9be55c427eb796c1932d8673579af1b4c638b0944489012a2559a3b02481b01ac30ba8960f80c0c2b3947d36a12c080498bee448716c973416c8242804a3da099ee137b0ba90fe4a5c6a89200276a0cfb643ec2c56a2d708d7b4373e44c1502a763a600586e6cda6273897d44448287dc2e602dc39200bf6166236559fd12a60892aeb153dd651bb469910b4b34669f91da8654d1eb72eb6e02800b3b0a7d0a48c836854d3a83e65569cb7230bb44f3f143a6dec5f2c39ab90f274f2088bd3d6a6fca0070273bedc84777fb52e3c558b0ae06183d5a48d452f68e15207f861627aca14279630f82ec3a0ca078633b600afa79743a600215be5637458ce2ce8aff5a08eb5017b2c766577479f8dc6bf9f5cc75089932161b96cea406620aedb630407f7687ebbb4814c7981637a48a90de68031e062a7af7612b4f5c7a6da86bd136529e64295a5613ea73bd3d4448cb81f243135c0a660beb9c17e651def469a7d90a15d3481090bcbf227012328941fa46f39c5006ad93d458aa6add655862b418c3094f551460df2153a5810a7da74f0614c2588be49dc6f5e88154642bd1d3762563326433507156a57c57694bdd26e7a246feb723aed67b04887c8e476b48cab59e5362f26a9ef50c2bc80ba146226216fe62968a60d04e8c170d741c7a2b0e1abdac968";

const KAT_KEYGEN_D_27_HEX: &str =
    "444f032dd19ae7518c4b35b0732a41dc567845aba8bd7b04a9c413a0cf2de0b5";

const KAT_KEYGEN_Z_27_HEX: &str =
    "df0f282411f4a071489a8f618e2ae5aef40131cac5233d6d731522720c2feb1c";

const KAT_KEYGEN_EK_27_HEX: &str = "5cc523b2d908c45907a6694a665195171a5b2fb583a5c240cadca8f0e83e46b14052c9620d3b7ef386ce8b9a5e873b65693b0d341c6eb2d10ce5e937cfb8c4c9134401babfeebbaecf47113a34b9c6e011bdc78a54f2b7bf36a5ffd27563d7443f2109f02a64c421411ddb2d1404a86f793a2de62cdc560bfd6604d4b6330ba6aa621414e8c12dc71c25652abaf36b875de1978dd209ab53b885206c3a1b4f8b4a0670c087cda9cda7997437155659255c2d024822a448ce5157cf5b6e4c495a949960886a902c79591120117c4a73ce7b380c661851e1ca9ef1973d8a9d2a191b938c4110259c4227b600ba7ec9b033bb0300715032836573382445435a743ca61e923b18adec7cfaf10ade908e582560ee91aca012942319b4888109e55aa738a7bcf777c92b4b09a50a1c043c982c2c2357f73c1687b35bd123fc905e1a719353466a42b915dbf1a1750339bf0923419681e4531d97e2160ad896db056570570510fb711169af2de0cba51c5f5056242965ad429301e7020ae0141f845833a3fba0b192426c001a7147c2926805cd86725442cadc2636bb769dcde46d1bd12d30f4695593b5753870ef796fb2f3a53f283d5828b77cb75d5de1ba25357c290a957fd501aee0ae59d7ae97833b0bb640f781a08bd256c79117c220bdd83280a0069b29a645720096d297a2e5245439268c0ed01f75a939978372b9e05d93da899c10bf6cdb18698c46ebe00bf90730e2ea393014461dec6c87f17b2ee16c13b8507c6009bee074f17367a5fc3067a28b7d804c32860ede650e6fe85cf6e301d1b1647323199ca296abc54d2811507572b5dff92b54e3786d130938417624775d8534b0102b6b8006803ddb376eb830d1ca80e717bb7f260a5ca4a56bfc5da790151725942ae7c42b2b9e385b4e0f995d4402161070b73a6bb0cdb77ef11b1286d75e315635e719088dc7909d026b198ac93bb4b6fe395843a4428f75c0c1448c605a8caba0b8cd19ce465764b523628b3334e3885d68d5089e1a3045840c36a73aefe7b93ab357fd8a46d7547a8efb243e4953e67ca72cfa0b77835768aa0cd2d976820a97bc21c7033084ad45c0bf6b483aca8a485641eb55a47be36abceb96143ba90c515d5be8513bb994cfa88ff4b3600e34c1e656877606b6280384a0f481458044c47732fa9b58195a5dfb48636e1558c56a43cb6941dee5aeb1e27b89a7121be166879b62bc01619a9abe840cc678e028e9bc71ce233fd9db8816294d71f1a080101912920534750dde692f782bac4d4481a0900e6bb952ada798ee06232c200f57f76a914617914b7398a0433cd7a11b5ac09789034f39338ce567e3e7aefe35b0c3b85d21506e8886587670761af9bad3261daf22cbfc664604234b3b784ea001cc6702b9222545cfdb2965eb54678780ee3c9cc134cd2e655908d6bdf460bee364c66d5accf4b492ade9a0f3eb31995badde4628b67165ff6014d848541035cda46949ec1c12ff492726a7214d1c7273fb85d5484e5a178751b56e3fb163d13a53c7b3038e09b847a8c06ff9b42e8c345cc95aac1a09660ac1fc7a146e7845ab83390871655e604c4c009ee924ae107b61bc3664f488ac60783a1c346bd18c56ced3f03bc1b1e4075e9785f235ebc5ce6621414e77d52cec3b2e";

const KAT_ENCAP_EK_HEX: &str = "89d2cb65f94dcbfc890efc7d0e5a7a38344d1641a3d0b024d50797a5f23c3a18b3101a1269069f43a842bacc098a8821271c673db1beb33034e4d7774d16635c7c2c3c2763453538bc1632e1851591a51642974e5928abb8e55fe55612f9b141aff015545394b2092e590970ec29a7b7e7aa1fb4493bf7cb731906c2a5cb49e6614859064e19b8fa26af51c44b5e7535bfdac072b646d3ea490d277f0d97ced47395fed91e8f2bce0e3ca122c2025f74067ab928a822b35653a74f06757629afb1a1caf237100ea935e793c8f58a71b3d6ae2c8658b10150d4a38f572a0d49d28ae89451d338326fdb3b4350036c1081117740edb86b12081c5c1223dbb5660d5b3cb3787d481849304c68be875466f14ee5495c2bd795ae412d09002d65b8719b90cba3603ac4958ea03cc138c86f7851593125334701b677f82f4952a4c93b5b4c134bb42a857fd15c650864a6aa94eb691c0b691be4684c1f5b7490467fc01b1d1fda4dda35c4ecc231bc73a6fef42c99d34eb82a4d014987b3e386910c62679a118f3c5bd9f467e4162042424357db92ef484a4a1798c1257e870a30cb20aaa0335d83314fe0aa7e63a862648041a72a6321523220b1ace9bb701b21ac1253cb812c15575a9085eabeade73a4ae76e6a7b158a20586d78a5ac620a5c9abcc9c043350a73656b0abe822da5e0ba76045fad75401d7a3b703791b7e99261710f86b72421d240a347638377205a152c794130a4e047742b888303bddc309116764de7424cebea6db65348ac537e01a9cc56ea667d5aa87ac9aaa4317d262c10143050b8d07a728ca633c13e468abcead372c77b8ecf3b986b98c1e55860b2b4216766ad874c35ed7205068739230220b5a2317d102c598356f168acbe80608de4c9a710b8dd07078cd7c671058af1b0b8304a314f7b29be78a933c7b9294424954a1bf8bc745de86198659e0e1225a910726074969c39a97c19240601a46e013dcdcb677a8cbd2c95a40629c256f24a328951df57502ab30772cc7e5b850027c8551781ce4985bdacf6b865c104e8a4bc65c41694d456b7169e45ab3d7acabeafe23ad6a7b94d1979a2f4c1cae7cd77d681d290b5d8e451bfdcccf5310b9d12a88ec29b10255d5e17a192670aa9731c5ca67ec784c502781be8527d6fc003c6701b3632284b40307a527c7620377feb0b73f722c9e3cd4dec64876b93ab5b7cfc4a657f852b659282864384f442b22e8a21109387b8b47585fc680d0ba45c7a8b1d7274bda57845d100d0f42a3b74628773351fd7ac305b2497639be90b3f4f71a6aa3561eecc6a691bb5cb3914d8634ca1e1af543c049a8c6e868c51f0423bd2d5ae09b79e57c27f3fe3ae2b26a441babfc6718ce8c05b4fe793b910b8fbcbbe7f1013242b40e0514d0bdc5c88bac594c794ce5122fbf34896819147b928381587963b0b90034aa07a10be176e01c80ad6a4b71b10af4241400a2a4cbbc05961a15ec1474ed51a3cc6d35800679a462809caa3ab4f7094cd6610b4a700cba939e7eac93e38c99755908727619ed76a34e53c4fa25bfc97008206697dd145e5b9188e5b014e941681e15fe3e132b8a3903474148ba28b987111c9bcb3989bbbc671c581b44a492845f288e62196e471fed3c39c1bbddb0837d0d4706b0922c4";

const KAT_ENCAP_M_HEX: &str = "2ce74ad291133518fe60c7df5d251b9d82add48462ff505c6e547e949e6b6bf7";

const KAT_ENCAP_C_HEX: &str = "56b42d593aab8e8773bd92d76eabddf3b1546f8326f57a7b773764b6c0dd30470f68dff82e0dca92509274ecfe83a954735fde6e14676daaa3680c30d524f4efa79ed6a1f9ed7e1c00560e8683538c3105ab931be0d2b249b38cb9b13af5ceaf7887a59dba16688a7f28de0b14d19f391eb41832a56479416ccf94e997390ed7878eeaff49328a70e0ab5fce6c63c09b35f4e45994de615b88bb722f70e87d2bbd72ae71e1ee9008e459d8e743039a8ddeb874fce5301a2f8c0ee8c2fee7a4ee68b5ed6a6d9ab74f98bb3ba0fe89e82bd5a525c5e8790f818ccc605877d46c8bdb5c337b025bb840ff471896e43bfa99d73dbe31805c27a43e57f0618b3ae522a4644e0d4e4c1c548489431be558f3bfc50e16617e110dd7af9a6fd83e3fbb68c304d15f6cb700d61d7aa915a6751ea3ba80223e654132a20999a43bf408592730b9a9499636c09fa729f9cb1f9d3442f47357a2b9cf15d3103b9bf396c23088f118ede346b5c03891cfa5d517cef8471322e7e31087c4b036abad784bff72a9b11fa198facbcb91f067feaf76fcfe5327c1070b3da6988400756760d2d1f060298f1683d51e3616e98c51c9c03aa42f2e633651a47ad3cc2ab4a852ae0c4b04b4e1c3dd944445a2b12b4f42a6435105c04122fc3587afe409a00b308d63c5dd8163654504eedbb7b5329577c35fbeb3f463872cac28142b3c12a740ec6ea7ce9ad78c6fc8fe1b4df5fc55c1667f31f2312da07799dc870a478608549fedafe021f1cf2984180364e90ad98d845652aa3cdd7a8eb09f5e51423fab42a7b7bb4d514864be8d71297e9c3b17a993f0ae62e8ef52637bd1b885bd9b6ab727854d703d8dc478f96cb81fce4c60383ac01fcf0f971d4c8f352b7a82e218652f2c106ca92ae686bacfcef5d327347a97a9b375d67341552bc2c538778e0f9801823ccdfcd1eaaded55b18c9757e3f212b2889d3857db51f981d16185fd0f900853a75005e3020a8b95b7d8f2f2631c70d78a957c7a62e1b3719070acd1fd480c25b83847da027b6ebbc2eec2df22c87f9b46d5d7baf156b53cee929572b92c4784c4e829f3446a1ffe47f99decd0436029ddebd3ed8e87e5e73d123dbe8a4ddacf2abde87f33ae2b621c0ec5d5cad1259deec2aeff6088f04f27a20338b5762543e5100899a4cbfb7b3ca456b3a19b83a4c432230c23e1c7f107c4cb112152f1c0f30da0bb33f4f11f47eea43872bafa84ae22256d708e0604dade4b2a4dde8cccf11930e13553934ae3ece52f3d7ccc00287377879fe6b8ece7ef79423507c9da339559c20de1c51955999bae47401dc3cdfaa1b256d09c7db9fc8698bfcefa7302d56fbcde1fbaaa1c653454e6fd3d84e4f79a931c681cbb6cb462b10dae112bdfb7f65c7fdf6e5fc594ec3a474a94bd97e6ec81f71c230bf70ca0f13ce3dffbd9ff9804efd8f37a4d3629b43a8f55544ebc5ac0abd9a33d79699068346a0f1a3a96e115a5d80be165b562d082984d5aacc3a2301981a6418f8ba7d7b0d7ca5875c6";

const KAT_ENCAP_K_HEX: &str = "2696d28e9c61c2a01ce9b1608dcb9d292785a0cd58efb7fe13b1de95f0db55b3";

const KAT_DECAP_DK_HEX: &str = "1e4ac87b1a692a529fdbbab93374c57d110b10f2b1ddebac0d196b7ba631b8e9293028a8f379888c422dc8d32bbf226010c2c1ec73189080456b0564b258b0f23131bc79c8e8c11cef3938b243c5ce9c0edd37c8f9d29877dbbb615b9b5ac3c948487e467196a9143efbc7cedb64b45d4acda2666cbc2804f2c8662e128f6a9969ec15bc0b9351f6f96346aa7abc743a14fa030e37a2e7597bddfc5a22f9cedaf8614832527210b26f024c7f6c0dcf551e97a4858764c321d1834ad51d75bb246d277237b7bd41dc4362d063f4298292272d01011780b79856b296c4e946658b79603197c9b2a99ec66acb06ce2f69b5a5a61e9bd06ad443ceb0c74ed65345a903b614e81368aac2b3d2a79ca8ccaa1c3b88fb82a36632860b3f7950833fd0212ec96ede4ab6f5a0bda3ec6060a658f9457f6cc87c6b620c1a1451987486e496612a101d0e9c20577c571edb5282608bf4e1ac926c0db1c82a504a799d89885ca6252bd5b1c183af701392a407c05b848c2a3016c40613f02a449b3c7926da067a533116506840097510460bbfd36073dcb0bfa009b36a9123eaa68f835f74a01b00d2097835964df521ce9210789c30b7f06e5844b444c53322396e4799baf6a88af7315860d0192d48c2c0da6b5ba64325543acdf5900e8bc477ab05820072d463affed097e062bd78c99d12b385131a241b708865b4190af69ea0a64db71448a60829369c7555198e438c9abc310bc70101913bb12faa5beef975841617c847cd6b336f877987753822020b92c4cc97055c9b1e0b128bf11f505005b6ab0e627795a20609efa991e598b80f37b1c6a1c3a1e9aee7028f77570ab2139128a00108c50eb305cdb8f9a603a6b078413f6f9b14c6d82b5199ce59d887902a281a027b717495fe12672a127bbf9b256c43720d7c160b281c12757da135b1933352be4ab67e40248afc318e2370c3b8208e695bdf337459b9acbfe5b487f76e9b4b4001d6cf90ca8c699a174d42972dc733f33389fdf59a1daba81d834955027334185ad02c76cf294846ca9294ba0ed66741ddec791cab34196ac5657c5a78321b56c33306b5102397a5c09c3508f76b48282459f81d0c72a43f737bc2f12f45422628b67db51ac1424276a6c08c3f7615665bbb8e928148a270f991bcf365a90f87c30687b68809c91f231813b866bea82e30374d80aa0c02973437498a53b14bf6b6ca1ed76ab8a20d54a083f4a26b7c038d81967640c20bf4431e71dacce8577b21240e494c31f2d877daf4924fd39d82d6167fbcc1f9c5a259f843e30987ccc4bce7493a2404b5e44387f707425781b743fb555685584e2557cc038b1a9b3f4043121f5472eb2b96e5941fec011ceea50791636c6abc26c1377ee3b5146fc7c85cb335b1e795eec2033ee44b9aa90685245ef7b4436c000e66bc8bcbf1cdb803ac1421b1fdb266d5291c8310373a8a3ce9562ab197953871ab99f382cc5aa9c0f273d1dca55d2712853871e1a83cb3b85450f76d3f3c42bab5505f7212fdb6b8b7f6029972a8f3751e4c94c1108b02d6ac79f8d938f05a1b2c229b14b42b31b01a364017e59578c6b033833774cb9b570f9086b722903b375446b495d8a29bf80751877a80fb724a0210c3e1692f397c2f1ddc2e6ba17af81b92acfabef5f7573cb493d184027b718238c89a3549b8905b28a83362867c082d3019d3ca70700731ceb73e8472c1a3a093361c5fea6a7d40955d07a41b64e50081a361b604cc518447c8e25765ab7d68b243275207af8ca6564a4cb1e94199dba1878c59bec809ab48b2f211badc6a1998d9c7227c1303f469d46a9c7e5303f98aba67569ae8227c16ba1fb3244466a25e7f823671810cc26206feb29c7e2a1a91959eeb03a98252a4f7412674eb9a4b277e1f2595fca64033b41b40330812e9735b7c607501cd8183a22afc3392553744f33c4d202526945c6d78a60e201a16987a6fa59d94464b56506556784824a07058f57320e76c825b9347f2936f4a0e5cdaa18cf8833945ae312a36b5f5a3810aac82381fdae4cb9c6831d8eb8abab850416443d739086b1c326fc2a3975704e396a59680c3b5f360f5480d2b62169cd94ca71b37bc5878ba2985e068ba050b2ce50726d4b4451b77aaa8676eae094982210192197b1e92a27f59868b78867887b9a70c32af84630aa908814379e6519150ba16439b5e2b0603d06aa6674557f5b0983e5cb6a97596069b01bb3128c416680657204fd07640392e16b19f337a99a304844e1aa474e9c799062971f672268960f5a82f950070bbe9c2a71950a3785bdf0b8440255ed63928d257845168b1eccc4191325aa76645719b28ebd89302dc6723c786df5217b243099ca78238e57e64692f206b177abc259660395cd7860fb35a16f6b2fe6548c85ab66330c517fa74cdf3cb49d26b1181901af775a1e180813b6a24c456829b5c38104ece43c76a437a6a33b6fc6c5e65c8a89466c1425485b29b9e1854368afca353e143d0a90a6c6c9e7fdb62a606856b5614f12b64b796020c3534c3605cfdc73b86714f411850228a28b8f4b49e663416c84f7e381f6af1071343bf9d39b45439240cc03897295fea080b14bb2d8119a880e164495c61bebc7139c11857c85e1750338d6343913706a507c9566464cd2837cf914d1a3c35e89b235c6ab7ed078bed234757c02ef6993d4a273cb8150528da4d76708177e9425546c83e147039766603b30da6268f4598a53194240a2832a3d67533b5056f9aaac61b4b17b9a2693aa0d58891e6cc56cdd772410900c405af20b903797c64876915c37b8487a1449ce924cd345c29a36e08238f7a157cc7e516ab5ba73c8063f726bb5a0a0319e57127438c7fc601c99ccaae4c1a83726fdcb5045ed1a82a985ea995396d77272c66ce493289f6110910f37c2741ce47026a6f8261999c6482572b1693912ef12eebea7acf9234fb409f2a6090e6b0bfd895469d0b2a921bb723f87a33ea5465ab90f514b67698c0768b6ca498b022c512fa0875f054aa2265867e31c0e522651e024a07d60dd9f633166921f4126bc2b6aa01cc15a09b85bff8218c5aae95bc1ffb26ae5a137670f04910ca9d7241b6660c394c5455917746a26682fb71a432ea9530e839bdeb07433004f45a0ddaa0b24e3a566a540815f281e3fc259ac6cbc0acb8d62268b603bc676ab415c474bb94873e4487ae31a4e3845c79901550890ee8784eef904fee62ba8c5f952c68413052e0a7e3388bb8ff0ad602ae3ea14d9df6dd5e4cc6a381a41da5c137ecc49df587e178eaf47702ec623780691a3233f69f12bd9c9b9637c51378ad71a831055277254cc63c5ad4cb76b4ab82e5fca135e8d26a6b3a89fa5b6f";

const KAT_DECAP_CT_OK_HEX: &str = "a5c81c76c24305e1ce5d8135d41523682e9ee6d7b40ad41df1f37c9b17dce78076019a6b0b7c95c9be7af29507b2d5a6987c8ee3259190855243e6e56f5620608c52d96fab103a8700fba1a87dca6078118a0871762c9534c0c0c3978c91c3a01f0f608dcf757815438fe8957c8a859183b1b6721a0865bebc799d4e5c0e7bd3eae4858e6ab6a2e7658ed80d4ed158b036b93fa03afa6ae3136cf3d693c911bcc75905e5b0cb2865b9e9884522a77777613e53111d5a1c7d3dab734ceb03657ae0c89763e99471054776bae7d51b0e73a5bb35aec30ff6bc93684916fef1162586452f426653e2ca844d5744307ff9aeb287a6447783b21a0e939c81421d631f5dcb452e51ed34e3dad1cf504e0a3b0f4711a8dc6499d1691d109569336ce1558a4c0a464e2087ea8f9e3b18f747ef61f4576aeb42b17cadb7f0fd84da8e3a6f471d95edfa65be9e6c9f6ae756a22a4f1a5c543c26ba7bad88e16d5f5b7e12e2d4ca34b3a64d17f87ccfc4ff8c5e4f53752a077c68721e8cc817f9ff24876170ff2af89fa95855a5b1de347c07fddbcfe7264aa5ed6401491561d831538f852b0ed7b9e8ebaffc060284f22d2baee56fa9f6d01432a115a2d6a64c38ae0a50ba362fb57b53e3e855b83ce8c42274045599f65fa6a8921d85f94ed230b516712db6fd2ff28b3a3371d9be058ae75c2fa591b7ec3c3daa1f7642bc26c324c08090607e6662154db37cf747967a1f9fc29089f570ebe60eeef89fd24481028c85aef1dc3b09f22cd3691bbbb821c7a8a0f35ad12be1dd199b977048f3d48c16bb2ca94cecb8928770d5bb329a0327e0b286faa1c65281031a31c84f2edc9c04d475ed4e128e51efa97d0148cba6c95f674c589f301c265bed708e9ad8da3c5cecbdeeed35ef1e253132ba89920d786b88230b013bcf2dc92d6b157afa8da8592cd0743d4982be60d7c2d5c472ab9fa7f4cc3d12b0ebaf0abe555c75805426844dd9428643f84406a1b8d6faedfd8ae6e73a72772a2159acabd972aeb6f7de091ac5fdd7f49a3dc6641cdf62446b4b04a31f73b80a62f80a404a8cb18ce3e65480ef7b52bf0091117e5d08eae1b0aabb72e6dffff76f6e44bbd7ea570d6604bc2e74318bafa315a38861aa1b21afb2a53f2614f1d640075984ae62e2fca1d1b4db369f15705ce7d4df8ae98264501051c0def21d645d49625af02ca428d9f0c2cd9fbaeeab97e8e9151662b6992b4c99ab1b925d08920363373f76d3fdf0828caa69c8b1bdc6f521df641cf1c8a4e7ef0c23289a4e2cf18acebbe4c1e68369bd5235120142ecdd1a73811e2e533a647d7aee16daa03b683639dcf1e1f1e71cfaed48f69aec3e831733da19cebec1ddbf71cbae0800f2f6d64a096ec495d62f4344f7aa5621b322353a795aa099ea3a070272d053d4653a20cf210eaaf12cae6023d8e5118df04b384a44d1edb91c44989ef7ee57f2bf81a24bdc76807da967ee6525410c5c485067efc3d39a9ad42cc753baa59a1fd28af35c00d18a406a28fc79ba";

const KAT_DECAP_K_OK_HEX: &str = "dc5b8888bc1eba5c1969c21164ea43e22e7ac0cd012a2f26cb8c487e69ef7ce4";

const KAT_DECAP_CT_BAD_HEX: &str = "74a26c7d27146a22c7eab420134e973799cec1da2df61ae0fa7905a3a47485a063076bfa22d6e4fe5059de0a32e38f11abd63f990e91bd0e3a5bc6e710dfe5dc0f6d4a18147ebc2e2d9b179374d83692c53efbd45f28a2a928c2494f903576c410eb1773895ebeadb119960eebda9c3c710795a6d9b781fc58b30d08107f4e20944a382afb079f31d21724f2c26e6a53412f0a908be7586f2b3d6d7c1dea0270e98aa209244bd88ed68aae01432342ba5f49e015cb476b5b78d15ea77a354cc9e9fd07137d8760be42fd4746c62c02028e7b405ddc95df3d021921cfeddb3d961b957eca302a263dab2dc117beb3e79efacfcf936dfc09fc0d19c358d724fa381ea06ca067c384e944302c3907ab15a1da4b41352692add59b061541f07eff25ec42f46e1a0e370cad06ff3fd997d4d2c5648af762231b382d0593401936cba21551a2ae30d8e8effcf43916b83138bb5e610364429879fa9cdd5b7d3cf2feabaa1dc8d50ce69402e21103e795df7074d1fcf65f8a4e18986d5417780602c63be5a044863384bd3d8ffb685eac567ed8349dcf2ceb702b7375b145729998049d13e2cd466cf2231b9d3a20018ee908f8514a6c6a89df7232f91fcd84b81ebc8bc539e9a37a4324755564be1bf4fa1fb4571e0abbc9b52f9d090c33be599de6c8532c7cb7ec8b4e2d3c07505280e99923865903ffd18bc13b9c8164aa1eae84e38d3f57fdb8801785f105a6a8574bd2fe9bf305848e525330bc2d24f0257e47a4950f433a9233e8cdeba81dbae7d8c1a06d01f70de6ef663207d84952827bab3d451cbea0990007fbdb4240fe899a706f7c1563e05c70be9d575189ef83e0cf76195f6652491cce04f1ce2092170a92e0dd7301246a4c44fc0b4ee6aaa63fc7027840abd2ec25f654589738cd38b9e10b975cfb6c1d2eb4da97736998f84fdddd810d72da3c5ab13507420ddbfaa4f7750c1fae9c7dfb30f40a12aea689fc78da900020e3abb32a364d5c6b3c7544a1b5734a41e95c8314b448cd0b738d829af772a8f81c51adba2d85f326c8f5d6961cf12d44a9bedea00d1df5b48f429b1ce0c15ea5f5bc10b017247ba2c6be922b0563b8e9698677cb6c45ccf2081bf84219d2904c11ff92199f8aefad62d8608e200802c5a07202cc820e9e520e31bf36a83002eca4018b0b3a398801562aa86c77ab0d50a8fbc3768b0a643b97e7f9072168de29b8175999c9aa48d301a3f0303172e9c7d4f16329d5ca9d42397c3982e10c9da42de88bd6c2ab91c1e71e778e58bb8f801f207a88a9b47f9c687afbba34eda6d2899e4fa0008aa2b539711753dc7c07f614e814f683d6c037562ae1fbbe6d7d5fa54b7a6d9451e11b01aaccc3bf2ed64742dd100e0eab2df6cccf937b6d5981eca0e01f3245cf26a72ad1adf066c8f5430d72f509963a657d85e554c14e26e8bec5d5f3ab998c9b29f16b04747d80749b30e51fd2a7f690c22f9986aaf6358d6fab8ded54971b32641de2b258590eeaa6bf1f32324a7c4c983f49466d86";

const KAT_DECAP_K_BAD_HEX: &str =
    "3d23b10df232a180786f61261e85278251746580bebca6acbad60aef6952be69";

/// The plan section 4.5 golden shared secret bytes: 0x00..=0x1f.
fn golden_shared_secret_bytes() -> [u8; ML_KEM_768_SHARED_SECRET_LEN] {
    let mut ss = [0u8; ML_KEM_768_SHARED_SECRET_LEN];
    for (i, byte) in ss.iter_mut().enumerate() {
        *byte = i as u8;
    }
    ss
}

/// The golden shared secret as the type `derive_tunnel_psk` accepts.
fn golden_shared_secret() -> MlKemSharedSecret {
    MlKemSharedSecret::from_bytes(golden_shared_secret_bytes())
}

fn hex_decode(hex: &str) -> Vec<u8> {
    let bytes = hex.as_bytes();
    (0..hex.len() / 2)
        .map(|i| {
            u8::from_str_radix(core::str::from_utf8(&bytes[2 * i..2 * i + 2]).unwrap(), 16).unwrap()
        })
        .collect()
}

/// Deterministic test RNG (xorshift* with a splitmix64 step). Only used to
/// drive keygen/encapsulation in tests; no production path constructs an RNG.
struct TestRng {
    state: u64,
}

impl TestRng {
    fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }
}

impl rand_core::TryRng for TestRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        Ok(z ^ (z >> 31))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let value = self.try_next_u64()?.to_le_bytes();
            for (dst, src) in chunk.iter_mut().zip(value) {
                *dst = src;
            }
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for TestRng {}

// ---------- plan section 4.5 golden vector ----------

#[test]
fn golden_vector_matches_plan_section_4_5() {
    let psk = derive_tunnel_psk(
        &golden_shared_secret(),
        "rustynet-demo",
        "node-alpha",
        "node-beta",
        1,
    )
    .unwrap();
    let expected: [u8; TUNNEL_PSK_LEN] = hex_decode(GOLDEN_PSK_HEX).try_into().unwrap();
    assert_eq!(*psk, expected);
}

#[test]
fn golden_vector_info_string_is_exact() {
    let psk = derive_tunnel_psk(
        &golden_shared_secret(),
        "rustynet-demo",
        "node-alpha",
        "node-beta",
        1,
    )
    .unwrap();
    // Independent re-derivation of the whole construction with the exact
    // info hex from plan section 4.5.
    let salt = b"rustynet-demo";
    let info = hex_decode(GOLDEN_INFO_HEX);
    let mut okm = [0u8; TUNNEL_PSK_LEN];
    Hkdf::<Sha256>::new(Some(salt), &golden_shared_secret_bytes())
        .expand(&info, &mut okm)
        .unwrap();
    assert_eq!(okm, *psk);
}

// ---------- derivation properties ----------

#[test]
fn canonical_order_is_order_independent() {
    let ss = golden_shared_secret();
    let cases = [
        ("node-alpha", "node-beta"),
        ("node-b", "node-a"),
        ("same-node", "same-node"),
        // Multibyte UTF-8: ordering is by UTF-8 bytes, not chars.
        ("nödé-Ω", "nödé-A"),
        ("n1", "n10"),
    ];
    for (a, b) in cases {
        let ab = derive_tunnel_psk(&ss, "rustynet-demo", a, b, 1).unwrap();
        let ba = derive_tunnel_psk(&ss, "rustynet-demo", b, a, 1).unwrap();
        assert_eq!(ab, ba, "order must not matter for ({a}, {b})");
    }
}

#[test]
fn length_prefixes_are_injective_pairing_boundary() {
    let ss = golden_shared_secret();
    let a_bc = derive_tunnel_psk(&ss, "rustynet-demo", "a", "bc", 1).unwrap();
    let ab_c = derive_tunnel_psk(&ss, "rustynet-demo", "ab", "c", 1).unwrap();
    assert_ne!(a_bc, ab_c, "(a, bc) and (ab, c) must derive different PSKs");
}

#[test]
fn network_id_separates_derivations() {
    let ss = golden_shared_secret();
    let demo = derive_tunnel_psk(&ss, "rustynet-demo", "node-alpha", "node-beta", 1).unwrap();
    let other = derive_tunnel_psk(&ss, "rustynet-other", "node-alpha", "node-beta", 1).unwrap();
    assert_ne!(demo, other);
}

#[test]
fn shared_secret_binds_the_psk() {
    let mut other_bytes = golden_shared_secret_bytes();
    other_bytes[0] ^= 0x01;
    let other_ss = MlKemSharedSecret::from_bytes(other_bytes);
    let demo = derive_tunnel_psk(
        &golden_shared_secret(),
        "rustynet-demo",
        "node-alpha",
        "node-beta",
        1,
    )
    .unwrap();
    let other =
        derive_tunnel_psk(&other_ss, "rustynet-demo", "node-alpha", "node-beta", 1).unwrap();
    assert_ne!(demo, other);
}

// ---------- refusals (Err, never panic) ----------

#[test]
fn derive_refuses_unsupported_versions() {
    let ss = golden_shared_secret();
    for version in [0u16, 2, 65535] {
        let err = derive_tunnel_psk(&ss, "rustynet-demo", "node-alpha", "node-beta", version)
            .unwrap_err();
        assert_eq!(
            err,
            MlKemError::UnsupportedPskDerivationVersion { got: version }
        );
    }
}

#[test]
fn derive_refuses_empty_node_ids() {
    let ss = golden_shared_secret();
    for (a, b) in [("", "node-beta"), ("node-alpha", "")] {
        let err = derive_tunnel_psk(&ss, "rustynet-demo", a, b, 1).unwrap_err();
        assert_eq!(err, MlKemError::EmptyNodeId);
    }
}

#[test]
fn derive_refuses_node_ids_longer_than_u16() {
    let ss = golden_shared_secret();
    let too_long: String = "n".repeat(u16::MAX as usize + 1);
    let err = derive_tunnel_psk(&ss, "rustynet-demo", "node-alpha", &too_long, 1).unwrap_err();
    assert_eq!(
        err,
        MlKemError::NodeIdTooLong {
            max: u16::MAX as usize,
            got: u16::MAX as usize + 1,
        }
    );
    // Exactly u16::MAX bytes is accepted (boundary).
    let max_len: String = "n".repeat(u16::MAX as usize);
    assert!(derive_tunnel_psk(&ss, "rustynet-demo", "node-alpha", &max_len, 1).is_ok());
}

#[test]
fn key_parsing_refuses_bad_lengths() {
    assert_eq!(
        MlKem768DecapsulationKey::from_seed(&[0u8; ML_KEM_768_SEED_LEN - 1]).err(),
        Some(MlKemError::InvalidSeedLength {
            expected: ML_KEM_768_SEED_LEN,
            got: ML_KEM_768_SEED_LEN - 1,
        })
    );
    assert_eq!(
        MlKem768EncapsulationKey::from_bytes(&[0u8; ML_KEM_768_ENCAPSULATION_KEY_LEN + 1]).err(),
        Some(MlKemError::InvalidEncapsulationKeyLength {
            expected: ML_KEM_768_ENCAPSULATION_KEY_LEN,
            got: ML_KEM_768_ENCAPSULATION_KEY_LEN + 1,
        })
    );
    assert_eq!(
        MlKem768Ciphertext::from_bytes(&[0u8; ML_KEM_768_CIPHERTEXT_LEN - 1]).err(),
        Some(MlKemError::InvalidCiphertextLength {
            expected: ML_KEM_768_CIPHERTEXT_LEN,
            got: ML_KEM_768_CIPHERTEXT_LEN - 1,
        })
    );
}

// ---------- KAT: key generation (key-gen.json) ----------

fn kat_keypair(d_hex: &str, z_hex: &str, ek_hex: &str) {
    let mut seed = hex_decode(d_hex);
    seed.extend(hex_decode(z_hex));
    assert_eq!(seed.len(), ML_KEM_768_SEED_LEN);
    let dk = MlKem768DecapsulationKey::from_seed(&seed).unwrap();
    let ek = dk.encapsulation_key();
    assert_eq!(ek.as_bytes().as_slice(), hex_decode(ek_hex).as_slice());
}

#[test]
fn kat_keygen_tc_id_26() {
    kat_keypair(
        KAT_KEYGEN_D_26_HEX,
        KAT_KEYGEN_Z_26_HEX,
        KAT_KEYGEN_EK_26_HEX,
    );
}

#[test]
fn kat_keygen_tc_id_27() {
    kat_keypair(
        KAT_KEYGEN_D_27_HEX,
        KAT_KEYGEN_Z_27_HEX,
        KAT_KEYGEN_EK_27_HEX,
    );
}

// ---------- KAT: encapsulation (encap-decap.json tgId 2) ----------

#[test]
fn kat_encapsulation_tc_id_26_deterministic() {
    // Deterministic path reproduces exactly the KAT (c, k) pair.
    let inner_ek = ml_kem::EncapsulationKey768::new(
        &<ml_kem::Key<ml_kem::EncapsulationKey768>>::try_from(
            hex_decode(KAT_ENCAP_EK_HEX).as_slice(),
        )
        .unwrap(),
    )
    .unwrap();
    let m = <ml_kem::B32>::try_from(hex_decode(KAT_ENCAP_M_HEX).as_slice()).unwrap();
    let (c, k) = inner_ek.encapsulate_deterministic(&m);
    assert_eq!(c.as_slice(), hex_decode(KAT_ENCAP_C_HEX).as_slice());
    assert_eq!(k.as_slice(), hex_decode(KAT_ENCAP_K_HEX).as_slice());

    // The public wrapper parses the same ACVP key bytes. Encapsulation with a
    // random message is exercised elsewhere (round_trip_matches_shared_secret);
    // this group ships no matching dk, so no cross-key roundtrip here.
    let ek = MlKem768EncapsulationKey::from_bytes(&hex_decode(KAT_ENCAP_EK_HEX)).unwrap();
    let _ = ek.encapsulate(&mut TestRng::new(0x5EED_0001));
}

// ---------- KAT: decapsulation + implicit rejection (tgId 5) ----------

fn kat_decap_key() -> MlKem768DecapsulationKey {
    // The ACVP decapsulation group ships the legacy 2400-byte expanded key,
    // so the (deprecated) expanded-form parser is confined here, mirroring
    // the ml-kem crate's own test suite.
    #[allow(deprecated)]
    {
        use ml_kem::ExpandedKeyEncoding;
        let expanded_bytes = hex_decode(KAT_DECAP_DK_HEX);
        let expanded = ml_kem::array::Array::try_from(expanded_bytes.as_slice()).unwrap();
        let dk = ml_kem::DecapsulationKey768::from_expanded_bytes(&expanded).unwrap();
        MlKem768DecapsulationKey(dk)
    }
}

#[test]
fn kat_decapsulation_valid_ciphertext_tc_id_88() {
    let dk = kat_decap_key();
    let ct = MlKem768Ciphertext::from_bytes(&hex_decode(KAT_DECAP_CT_OK_HEX)).unwrap();
    let ss = dk.decapsulate(&ct).unwrap();
    let expected: [u8; ML_KEM_768_SHARED_SECRET_LEN] =
        hex_decode(KAT_DECAP_K_OK_HEX).try_into().unwrap();
    assert_eq!(*ss.expose(), expected);
}

#[test]
fn kat_implicit_rejection_substituted_ciphertext_tc_id_86() {
    let dk = kat_decap_key();
    let ct = MlKem768Ciphertext::from_bytes(&hex_decode(KAT_DECAP_CT_BAD_HEX)).unwrap();
    // Must not panic; the rejection secret is deterministic and known.
    let ss = dk.decapsulate(&ct).unwrap();
    let expected: [u8; ML_KEM_768_SHARED_SECRET_LEN] =
        hex_decode(KAT_DECAP_K_BAD_HEX).try_into().unwrap();
    assert_eq!(*ss.expose(), expected);
    // ...and it is not the valid shared secret.
    assert_ne!(
        ss.expose().as_slice(),
        hex_decode(KAT_DECAP_K_OK_HEX).as_slice()
    );
}

// ---------- composed round trips ----------

#[test]
fn round_trip_matches_shared_secret() {
    let (dk, ek) = generate_keypair(&mut TestRng::new(0x5EED_0002));
    let (ct, sender_ss) = ek.encapsulate(&mut TestRng::new(0x5EED_0003));
    let receiver_ss = dk.decapsulate(&ct).unwrap();
    assert_eq!(sender_ss.expose(), receiver_ss.expose());
}

#[test]
fn substituted_ciphertext_rejects_without_panic() {
    let (dk, ek) = generate_keypair(&mut TestRng::new(0x5EED_0004));
    let (ct, sender_ss) = ek.encapsulate(&mut TestRng::new(0x5EED_0005));

    // Flip one bit in the middle of the ciphertext.
    let mut tampered = ct.as_bytes().to_vec();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    let tampered = MlKem768Ciphertext::from_bytes(&tampered).unwrap();

    let receiver_ss = dk.decapsulate(&tampered).unwrap();
    assert_ne!(
        sender_ss.expose(),
        receiver_ss.expose(),
        "implicit rejection must not reproduce the sender's secret"
    );

    // A ciphertext belonging to a *different* keypair must also be rejected.
    let (other_dk, other_ek) = generate_keypair(&mut TestRng::new(0x5EED_0006));
    let (other_ct, _) = other_ek.encapsulate(&mut TestRng::new(0x5EED_0007));
    let cross = dk.decapsulate(&other_ct).unwrap();
    assert_ne!(sender_ss.expose(), cross.expose());
    let _ = other_dk;
}

#[test]
fn psk_derivation_composes_with_encapsulation() {
    let (dk, ek) = generate_keypair(&mut TestRng::new(0x5EED_0008));
    let (ct, sender_ss) = ek.encapsulate(&mut TestRng::new(0x5EED_0009));
    let receiver_ss = dk.decapsulate(&ct).unwrap();
    let a = derive_tunnel_psk(&sender_ss, "rustynet-demo", "node-alpha", "node-beta", 1).unwrap();
    let b = derive_tunnel_psk(&receiver_ss, "rustynet-demo", "node-alpha", "node-beta", 1).unwrap();
    assert_eq!(a, b);
}

#[test]
fn empty_network_id_is_refused() {
    let err = derive_tunnel_psk(&golden_shared_secret(), "", "node-alpha", "node-beta", 1)
        .expect_err("an empty network id must be refused");
    assert_eq!(err, MlKemError::EmptyNetworkId);
}
