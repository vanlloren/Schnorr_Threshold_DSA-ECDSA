//
// Created by PC on 14/05/2026.
//

#include "secp256r1_G_precomputed_table.h"

/********** Precomputed table for the generator G **********/
const secp256r1_point_ge SECP256R1_PRECOMPUTED_G[SECP256R1_PRECOMPUTED_G_SIZE] = {
        // 1G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x18A9143C, 0x79E730D4, 0x5FEDB601, 0x75BA95FC, 0x77622510, 0x79FB732B, 0xA53755C6, 0x18905F76 },
                .y = { 0xCE95560A, 0xDDF25357, 0xBA19E45C, 0x8B4AB8E4, 0xDD21F325, 0xD2E88688, 0x25885D85, 0x8571FF18 }
        },
        // 2G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x10DDD64D, 0x850046D4, 0xA433827D, 0xAA6AE3C1, 0x8D1490D9, 0x73220503, 0x3DCF3A3B, 0xF6BB32E4 },
                .y = { 0x61BEE1A5, 0x2F3648D3, 0xEB236FF8, 0x152CD7CB, 0x92042DBE, 0x19A8FB0E, 0x0A5B8A3B, 0x78C57751 }
        },
        // 3G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x4EEBC127, 0xFFAC3F90, 0x087D81FB, 0xB027F84A, 0x87CBBC98, 0x66AD77DD, 0xB6FF747E, 0x26936A3F },
                .y = { 0xC983A7EB, 0xB04C5C1F, 0x0861FE1A, 0x583E47AD, 0x1A2EE98E, 0x78820831, 0xE587CC07, 0xD5F06A29 }
        },
        #if (SECP256R1_WINDOW_SIZE > 2)
        // 4G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x46918DCC, 0x74B0B50D, 0xC623C173, 0x4650A6ED, 0xE8100AF2, 0x0CDAACAC, 0x41B0176B, 0x577362F5 },
                .y = { 0xE4CBABA6, 0x2D96F24C, 0xFAD6F447, 0x17628471, 0xE5DDD22E, 0x6B6C36DE, 0x4C5AB863, 0x84B14C39 }
        },
        // 5G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC45C61F5, 0xBE1B8AAE, 0x94B9537D, 0x90EC649A, 0xD076C20C, 0x941CB5AA, 0x890523C8, 0xC9079605 },
                .y = { 0xE7BA4F10, 0xEB309B4A, 0xE5EB882B, 0x73C568EF, 0x7E7A1F68, 0x3540A987, 0x2DD1E916, 0x73A076BB }
        },
        // 6G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x3E77664A, 0x40394737, 0x346CEE3E, 0x55AE744F, 0x5B17A3AD, 0xD50A961A, 0x54213673, 0x13074B59 },
                .y = { 0xD377E44B, 0x93D36220, 0xADFF14B5, 0x299C2B53, 0xEF639F11, 0xF424D44C, 0x4A07F75F, 0xA4C9916D }
        },
        // 7G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xA0173B4F, 0x0746354E, 0xD23C00F7, 0x2BD20213, 0x0C23BB08, 0xF43EAAB5, 0xC3123E03, 0x13BA5119 },
                .y = { 0x3F5B9D4D, 0x2847D030, 0x5DA67BDD, 0x6742F2F2, 0x77C94195, 0xEF933BDC, 0x6E240867, 0xEAEDD915 }
        },
        // 8G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x9499A78F, 0x27F14CD1, 0x6F9B3455, 0x462AB5C5, 0xF02CFC6B, 0x8F90F02A, 0xB265230D, 0xB763891E },
                .y = { 0x532D4977, 0xF59DA3A9, 0xCF9EBA15, 0x21E3327D, 0xBE60BBF0, 0x123C7B84, 0x7706DF76, 0x56EC12F2 }
        },
        // 9G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x264E20E8, 0x75C96E8F, 0x59A7A841, 0xABE6BFED, 0x44C8EB00, 0x2CC09C04, 0xF0C4E16B, 0xE05B3080 },
                .y = { 0xA45F3314, 0x1EB7777A, 0xCE5D45E3, 0x56AF7BED, 0x88B12F1A, 0x2B6E019A, 0xFD835F9B, 0x086659CD }
        },
        // 10G  corretto
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x9DC21EC8, 0x2C18DBD1, 0x0FCF8139, 0x98F9868A, 0X48250B49, 0x737D2CD6, 0x24B3428F, 0xCC61C947 },
                .y = { 0x80DD9E76, 0x0C2B4078, 0x383FBE08, 0xC43A8991, 0x779BE5D2, 0x5F7D2D65, 0xEB3B4AB5, 0x78719A54 }
        },
        // 11G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x6245E404, 0xEA7D260A, 0x6E7FDFE0, 0x9DE40795, 0x8DAC1AB5, 0x1FF3A415, 0x649C9073, 0x3E7090F1 },
                .y = { 0x2B944E88, 0x1A768561, 0xE57F61C8, 0x250F939E, 0x1EAD643D, 0x0C0DAA89, 0xE125B88E, 0x68930023 }
        },
        // 12G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD2697768, 0x04B71AA7, 0xCA345A33, 0xABDEDEF5, 0xEE37385E, 0x2409D29D, 0xCB83E156, 0x4EE1DF77 },
                .y = { 0x1CBB5B43, 0x0CAC12D9, 0xCA895637, 0x170ED2F6, 0x8ADE6D66, 0x28228CFA, 0x53238ACA, 0x7FF57C95 }
        },
        // 13G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x4B2ED709, 0xCCC42563, 0x856FD30D, 0x0E356769, 0x559E9811, 0xBCBCD43F, 0x5395B759, 0x738477AC },
                .y = { 0xC00EE17F, 0x35752B90, 0x742ED2E3, 0x68748390, 0xBD1F5BC1, 0x7CD06422, 0xC9E7B797, 0xFBC08769 }
        },
        // 14G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xB0CF664A, 0xA242A35B, 0x7F9707E3, 0x126E48F7, 0xC6832660, 0x1717BF54, 0xFD12C72E, 0xFAAE7332 },
                .y = { 0x995D586B, 0x27B52DB7, 0x832237C2, 0xBE29569E, 0x2A65E7DB, 0xE8E4193E, 0x2EAA1BBB, 0x152706DC }
        },
        // 15G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xBC60055B, 0x72BCD8B7, 0x56E27E4B, 0x03CC23EE, 0xE4819370, 0xEE337424, 0x0AD3DA09, 0xE2AA0E43 },
                .y = { 0x6383C45D, 0x40B8524F, 0x42A41B25, 0xD7663554, 0x778A4797, 0x64EFA6DE, 0x7079ADF4, 0x2042170A }
        },
        #endif
        #if (SECP256R1_WINDOW_SIZE > 4)
        // 16G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x0BC6FB80, 0x808B0B65, 0x3FFE2E6B, 0x5882E075, 0x2C83F549, 0xD5EF2F7C, 0x9103B723, 0x54D63C80 },
                .y = { 0x52A23F9B, 0xF2F11BD6, 0x4B0B6587, 0x3670C319, 0xB1580E9E, 0x55C4623B, 0x01EFE220, 0x64EDF7B2 }
        },
        // 17G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD53C5C9D, 0x97091DCB, 0xAC0A177B, 0xF17624B6, 0x2CFE2DFF, 0xB0F13975, 0x6C7A574E, 0xC1A35C0A },
                .y = { 0x93E79987, 0x227D3146, 0xE89CB80E, 0x0575BF30, 0x0D1883BB, 0x2F4E247F, 0x3274C3D0, 0xEBD51226 }
        },
        // 18G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x56ADA97A, 0x5F3E51C8, 0x8F8B403E, 0x4AFC964D, 0x412E2979, 0xA6F247AB, 0x6F80EBDA, 0x675ABD1B },
                .y = { 0x5E485A1D, 0x66A2BD72, 0x8F4F0B3C, 0x4B2A5CAF, 0x1B847BBA, 0x2626927F, 0x0502394D, 0x6C6FC7D9 }
        },
        // 19G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xA5659AE8, 0xFEA912BA, 0x25E1A16E, 0x68363ABA, 0x752C41AC, 0xB8842277, 0x2897C3FC, 0xFE545C28 },
                .y = { 0xDC4C696B, 0x2D36E9E7, 0xFBA977C5, 0x5806244A, 0xE39508C1, 0x85665E9B, 0x6D12597B, 0xF720EE25 }
        },
        // 20G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD2337A31, 0x8A979129, 0x0F862BDC, 0x5916868F, 0x5DD283BA, 0x048099D9, 0xFE5BFB4E, 0xE2D1EEB6 },
                .y = { 0x7884005D, 0x82EF1C41, 0xFFFFCBAE, 0xA2D4EC17, 0x8AA95E66, 0x9161C53F, 0xC5FEE0D0, 0x5EE104E1 }
        },
        // 21G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC135B208, 0x562E4CEC, 0x4783F47D, 0x74E1B265, 0x5A3F3B30, 0x6D2A506C, 0xC16762FC, 0xECEAD9F4 },
                .y = { 0xE286E5B9, 0xF29DD4B2, 0x83BB3C61, 0x1B0FADC0, 0x7FAC29A4, 0x7A75023E, 0xC9477FA3, 0xC086D5F1 }
        },
        // 22G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x2F6F3076, 0x0FC61135, 0xE3912A9A, 0xC99FFA23, 0xD2F8BA3D, 0x6A0B0685, 0xE93358A4, 0xFDC777E8 },
                .y = { 0x35415F04, 0x94A787BB, 0x4D23FEA4, 0x640C2D6A, 0x153A35B5, 0x9DE917DA, 0x5D5CD074, 0x793E8D07 }
        },
        // 23G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x2DE45068, 0xF4F87653, 0x9E2E1F6E, 0x37C7A7E8, 0xA3584069, 0xD0825FA2, 0x1727BF42, 0xAF2CEA7C },
                .y = { 0x9E4785A9, 0x0360A4FB, 0x27299F4A, 0xE5FDA49C, 0x71AC2F71, 0x48068E13, 0x9077666F, 0x83D0687B }
        },
        // 24G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x15D02819, 0x6D3883B2, 0x40DD9A35, 0x6D0D7550, 0x1D2B469F, 0x61D7CBF9, 0x2EFC3115, 0xF97B232F },
                .y = { 0xB24BCBC7, 0xA551D750, 0x88A1E356, 0x11EA4949, 0x93CB7501, 0x7669F031, 0xCA737B8A, 0x595DC55E }
        },
        // 25G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD837879F, 0xA4A319AC, 0xED6B67B0, 0x6FC1B49E, 0x32F1F3AF, 0xE3959933, 0x65432A2E, 0x966742EB },
                .y = { 0xB4966228, 0x4B8DC9FE, 0x43F43950, 0x96CC6312, 0xC9B731EE, 0x12068859, 0x56F79968, 0x7B948DC3 }
        },
        // 26G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xED1F8008, 0x61E4AD32, 0xD8B17538, 0xE6C9267A, 0x857FF6FB, 0x1AC7C5EB, 0x55F2FB10, 0x994BAAA8 },
                .y = { 0x1D248018, 0x84CF14E1, 0x628AC508, 0x5A39898B, 0x5FA944F5, 0x14FDE97B, 0xD12E5AC7, 0xED178030 }
        },
        // 27G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x97E2FEB4, 0x042C2AF4, 0xAEBF7313, 0xD36A42D7, 0x084FFDD7, 0x49D2C9EB, 0x2EF7C76A, 0x9F8AA54B },
                .y = { 0x09895E70, 0x9200B7BA, 0xDDB7FB58, 0x3BD0C66F, 0x78EB4CBB, 0x2D97D108, 0xD84BDE31, 0x2D431068 }
        },
        // 28G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x172CCD1F, 0x4B523EB7, 0x30A6A892, 0x7323CB28, 0xCFE153EB, 0x97082EC0, 0xF2AADB97, 0xE97F6B6A },
                .y = { 0xD1A83DA1, 0x1D3D393E, 0x804B2A68, 0xA6A7F9C7, 0x2D0CB71E, 0x4A688B48, 0x40585278, 0xA9B4CC5F }
        },
        // 29G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xCB66E132, 0x5E5DB46A, 0x0D925880, 0xF1BE963A, 0x0317B9E2, 0x944A7027, 0x48603D48, 0xE266F959 },
                .y = { 0x5C208899, 0x98DB6673, 0xA2FB18A3, 0x90472447, 0x777C619F, 0x8A966939, 0x2A3BE21B, 0x3798142A }
        },
        // 30G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x3298B343, 0xB4241CB1, 0xB44F65A1, 0xA3A14E49, 0x3AC77ACD, 0xC5F4D6CD, 0x52B6FC3C, 0xD0288CB5 },
                .y = { 0x1C040ABC, 0xD5CC8C2F, 0x06BF9B4A, 0xB675511E, 0x9B3AA441, 0xD667DA37, 0x51601F72, 0x460D45CE }
        },
        // 31G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x6755FF89, 0xE2F73C69, 0x473017E6, 0xDD3CF7E7, 0x3CF7600D, 0x8EF5689D, 0xB1FC87B4, 0x948DC4F8 },
                .y = { 0x4EA53299, 0xD9E9FE81, 0x98EB6028, 0x2D921CA2, 0x0C9803FC, 0xFAECEDFD, 0x4D7B4745, 0xF38AE891 }
        },
        // 32G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC5E3A3D8, 0xD8C5FCCF, 0x4079DFBF, 0xBEFD904C, 0xFEAD0197, 0xBC6D6A58, 0x695532A4, 0x39227077 },
                .y = { 0xDBEF42F5, 0x09E23E6D, 0x480A9908, 0x7E449B64, 0xAD9A2E40, 0x7B969C1A, 0x9591C2A4, 0x6231D792 }
        },
        // 33G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x0F664534, 0x87151456, 0x4B68F103, 0x85CEAE7C, 0x65578AB9, 0xAC09C4AE, 0xF044B10C, 0x33EC6868 },
                .y = { 0x3A8EC1F1, 0x6AC4832B, 0x5847D5EF, 0x5509D128, 0x763F1574, 0xF909604F, 0xC32F63C4, 0xB16C4303 }
        },
        // 34G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x7CA23CD3, 0xB6AB2014, 0xA391849D, 0xCAA7A5C6, 0x75678D94, 0x5B0673A3, 0xDD303E64, 0xC982DDD4 },
                .y = { 0x5DB6F971, 0xFD7B000B, 0x6F876F92, 0xBBA2CB1F, 0x3C569426, 0xC77332A3, 0x570D74F8, 0xA159100C }
        },
        // 35G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xDEC67EF5, 0xFD16847F, 0x233E76B7, 0x742EE464, 0xEFC2B4C8, 0x0B8E4134, 0x42A3E521, 0xCA640B86 },
                .y = { 0x8CEB6AA9, 0x653A0190, 0x547852D5, 0x313C300C, 0x6B237AF7, 0x24E4AB12, 0x8BB47AF8, 0x2BA90162 }
        },
        // 36G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xA8219BB7, 0x3D5E58D6, 0x1B06C57F, 0xC691D0BD, 0xD257576E, 0x0AE4CB10, 0xD54A3DC3, 0x3569656C },
                .y = { 0x94CDA03A, 0xE5EBAEBD, 0x162BFE13, 0x934E82D3, 0xE251A0C6, 0x450AC0BA, 0xDD6DA526, 0x480B9E11 }
        },
        // 37G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x8CCE08B5, 0x00467BC5, 0x7F178D55, 0xB636458C, 0xA677D806, 0xC5748BAE, 0xDFA394EB, 0x2763A387 },
                .y = { 0x7D3CEBB6, 0xA12B448A, 0x6F20D850, 0xE7ADDA3E, 0x1558462C, 0xF63EBCE5, 0x620088A8, 0x58B36143 }
        },
        // 38G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x4D63C0EE, 0x8A2CC3CA, 0x0FE948CE, 0x51233117, 0x222EF33B, 0x7463FD85, 0x7C603D6C, 0xADF0C7DC },
                .y = { 0xFE7765E5, 0x0EC32D3B, 0xBF380409, 0xCCAAB359, 0x8E59319C, 0xBDAA84D6, 0x9C80C34D, 0xD9A4C280 }
        },
        // 39G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xA059C142, 0xA9D89488, 0xFF0B9346, 0x6F5AE714, 0x16FB3664, 0x068F237D, 0x363186AC, 0x5853E4C4 },
                .y = { 0x63C52F98, 0xE2D87D23, 0x81828876, 0x2EC4A766, 0xE14E7B1C, 0x47B864FA, 0x69192408, 0x0C0BC0E5 }
        },
        // 40G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xB82E9F3E, 0xE4D7681D, 0xDF25E13C, 0x83200F0B, 0x66F27280, 0x8909984C, 0x75F73227, 0x462D7B00 },
                .y = { 0xF2651798, 0xD90BA188, 0x36AB1C34, 0x74C6E18C, 0x5EF54359, 0xAB256EA3, 0xD1AA702F, 0x03466612 }
        },
        // 41G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x2ED22E91, 0x624D6049, 0x6F072822, 0x6FDFE0B5, 0x39CE2271, 0xEECA1115, 0xDB01614F, 0x98100A4F },
                .y = { 0xA35C628F, 0xB6B0DAA2, 0xC87E9A47, 0xB6F94D2E, 0x1D57D9CE, 0xC6773259, 0x03884A7B, 0xF70BFEEC }
        },
        // 42G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xED2BAD01, 0x5FB35CCF, 0x1DA6A5C7, 0xA155CBE3, 0x30A92F8F, 0xC2E2594C, 0x5BFAFE43, 0x649C89CE },
                .y = { 0xE9FF257A, 0xD158667D, 0xF32C50AE, 0x9B359611, 0x906014CF, 0x4B00B20B, 0x89BC7D3D, 0xF3A8CFE3 }
        },
        // 43G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x248A7D06, 0x4FF23FFD, 0x878873FA, 0x80C5BFB4, 0x05745981, 0xB7D9AD90, 0x3DB01994, 0x179C85DB },
                .y = { 0x61A6966C, 0xBA41B062, 0xEADCE5A8, 0x4D82D052, 0xA5E6A318, 0x9E91CD3B, 0x95B2DDA0, 0x47795F4F }
        },
        // 44G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD55A897C, 0xECFD7C1F, 0xB29110FB, 0x009194AB, 0xE381D3B0, 0x5F0E2046, 0xA98DD291, 0x5F3425F6 },
                .y = { 0x730D50DA, 0xBFA06687, 0x4B083B7F, 0x0423446C, 0xD69D3417, 0x397A247D, 0x387BA42A, 0xEB629F90 }
        },
        // 45G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD5CD79BF, 0x1EE426CC, 0x946C6E18, 0x0032940B, 0x57477F58, 0x1B1E8AE0, 0x6D823278, 0xE94F7D34 },
                .y = { 0x782BA21A, 0xC747CB96, 0xF72B33A5, 0xC5254469, 0xC7F80C81, 0x772EF6DE, 0x2CD9E6B5, 0xD73ACBFE }
        },
        // 46G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x49EE90D9, 0x4075B5B1, 0xA06E9EBA, 0x785C339A, 0xABF825E0, 0xA1030D5B, 0xA42931DC, 0xCEC684C3 },
                .y = { 0xC1586E63, 0x42AB62C9, 0x5AB43F2B, 0x45431D66, 0x55F7835D, 0x57C8B2C0, 0xC1B7F865, 0x033DA338 }
        },
        // 47G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xCAA76097, 0x283C7513, 0x36C83906, 0x0A624FA9, 0x715AF2C7, 0x6B20AFEC, 0xEBA78BFD, 0x4B969974 },
                .y = { 0xD921D60E, 0x220755CC, 0x7BAECA13, 0x9B944E10, 0x5DED93D4, 0x04819D51, 0x6DDDFD27, 0x9BBFF86E }
        },
        // 48G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x77ADC612, 0x6B344130, 0xBBD803A0, 0xA7496529, 0x6D8805BD, 0x1A1BAAA7, 0x470343AD, 0xC8403902 },
                .y = { 0x175ADFF1, 0x39F59F66, 0xB7D8C5B7, 0x0B26D7FB, 0x529D75E3, 0xA875F5CE, 0x41325CC2, 0x85EFC7E9 }
        },
        // 49G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x1FF6ACD3, 0x21950B42, 0x53DC6909, 0xFFE70484, 0x28766127, 0xFF4CD0B2, 0x4FB7DB2B, 0xABDBE608 },
                .y = { 0x5E1109E8, 0x837C9228, 0xF4645B5A, 0x26147D27, 0xF7818ED8, 0x4D78F592, 0xF247FA36, 0xD394077E }
        },
        // 50G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x488C171A, 0x0FB9C2D0, 0x13685278, 0xA78BFBAA, 0xD5B1FA6A, 0xEDFBE268, 0x2B7EABA7, 0x0DCEB8DB },
                .y = { 0x9AE2B710, 0xBF9E8089, 0xA4449C96, 0xEFDE7AE6, 0xCC143A46, 0x43B7716B, 0xC3628C13, 0xD7D34194 }
        },
        // 51G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x3B3F64C9, 0x508CEC1C, 0x1E5EDF3F, 0xE20BC0BA, 0x2F4318D4, 0xDA1DEB85, 0x5C3FA443, 0xD20EBE0D },
                .y = { 0x73241EA3, 0x370B4EA7, 0x5E1A5F65, 0x61F1511C, 0x82681C62, 0x99A5E23D, 0xA2F54C2D, 0xD731E383 }
        },
        // 52G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x83445904, 0x2692F36E, 0xAF45F9C0, 0x2E0EC469, 0xC67528B7, 0x905A3201, 0xD0E5E542, 0x88F77F34 },
                .y = { 0x5864687C, 0xF67A8D29, 0x22DF3562, 0x23B92EAE, 0x9BBEC39E, 0x5C27014B, 0x9C0F0F8D, 0x7EF2F226 }
        },
        // 53G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x546C4D8D, 0x97359638, 0x92F24679, 0x5F9C3FC4, 0xA8C8ACD9, 0x912E8BED, 0x306634B0, 0xEC3A318D },
                .y = { 0xC31CB264, 0x80167F41, 0x522113F2, 0x3DB82F6F, 0xDCAFE197, 0xB155BCD2, 0x43465283, 0xFBA1DA59 }
        },
        // 54G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xB212CF53, 0xA0425B8E, 0xF8557C5F, 0x4F2E512E, 0x25C4D56C, 0xC1286FF9, 0xEE26C851, 0xBB8A0FEA },
                .y = { 0xE7D6107E, 0xC28F70D2, 0xE76265AA, 0x7EE0C444, 0x1D1936B1, 0x3DF277A4, 0xEA9595EB, 0x1A556E3F }
        },
        // 55G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xE7305683, 0x258BBBF9, 0x07EF5BE6, 0x31EEA5BF, 0x46C814C1, 0x0DEB0E4A, 0xA7B730DD, 0x5CEE8449 },
                .y = { 0xA0182BDE, 0xEAB495C5, 0x9E27A6B4, 0xEE759F87, 0x80E518CA, 0xC2CF6A68, 0xF14CF3F4, 0x25E8013F }
        },
        // 56G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x7E8D7A14, 0x8FC44140, 0x9556F36A, 0xBB1FF3CA, 0x14600044, 0x6A844385, 0x7451AE63, 0xBA3F0C4A },
                .y = { 0x1F9AF32A, 0xDFCAC25B, 0xB1F2214B, 0x01E0DB86, 0xA4B596AC, 0x4E9A5BC2, 0x026C2C08, 0x83927681 }
        },
        // 57G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x7ACACA28, 0x3EC832E7, 0xC7385B29, 0x1BFEEA57, 0xFD1EAF38, 0x068212E3, 0x6ACF8CCC, 0xC1329830 },
                .y = { 0x2AAC9E59, 0xB909F2DB, 0xB661782A, 0x5748060D, 0xC79B7A01, 0xC5AB2632, 0x00017626, 0xDA44C6C6 }
        },
        // 58G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xA7EA82F0, 0xF26C00E8, 0xE4299AAF, 0x99CAC80D, 0x7ED78BE1, 0xD66FE3B6, 0x648D02CD, 0x305F725F },
                .y = { 0x623FB21B, 0x33ED1BC4, 0x7A6319AD, 0xFA70533E, 0xBE5FFB3E, 0x17AB562D, 0x56674741, 0x06374994 }
        },
        // 59G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x5C46AA8E, 0x69D44ED6, 0xA8D063D1, 0x2100D5D3, 0xA2D17C36, 0xCB9727EA, 0x8ADD53B7, 0x4C2BAB1B },
                .y = { 0x15426704, 0xA084E90C, 0xA837EBEA, 0x778AFCD3, 0x7CE477F8, 0x6651F701, 0x46FB7A8B, 0xA0624998 }
        },
        // 60G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xED8A6E19, 0xDC1E6828, 0x4189D9C7, 0x33FC2336, 0x671C39BC, 0x026F8FE2, 0xBC6F9915, 0xD40C4CCD },
                .y = { 0xF80E75CA, 0xAFA135BB, 0x22ADFF2C, 0x12C651A0, 0x4F51AD96, 0xC40A04BD, 0xBBE4E832, 0x04820109 }
        },
        // 61G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x7F4C04CC, 0x3667EB1A, 0xA9404F84, 0x59556621, 0x7ECEB50A, 0x71CDF653, 0x9B8335FA, 0x994A44A6 },
                .y = { 0xDBEB9B69, 0xD7FAF819, 0xEED4350D, 0x473C5680, 0xDA44BBA2, 0xB6658466, 0x872BDBF3, 0x0D1BC780 }
        },
        // 62G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xA1962F91, 0xE535F175, 0xED58F5A7, 0x6ED7E061, 0x2089A233, 0x177AA4C0, 0xE539B413, 0x0DBCB03A },
                .y = { 0xBB32E38E, 0xE3DC424E, 0x6806701E, 0x6472E5EF, 0x814BE9EE, 0xDD47FF98, 0x35ACE009, 0x6B60CFFF }
        },
        // 63G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x9FF91FE5, 0xB8D3D931, 0xF0518EED, 0x039C4800, 0x9182CB26, 0x95C37632, 0x82FC568D, 0x0763A434 },
                .y = { 0x383E76BA, 0x707C04D5, 0x824E8197, 0xAC98B930, 0x91230DE0, 0x92BF7C8F, 0x40959B70, 0x90876A01 }
        },
        // 64G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x05968B80, 0xDB6D96F3, 0x089F73B9, 0x380A0913, 0xC2C61E01, 0x7DA70B83, 0x569B38C7, 0x95FB8394 },
                .y = { 0x80EDFE2F, 0x9A3C6512, 0x8FAEAF82, 0x8F726BB9, 0x78424BF8, 0x8010A4A0, 0x0E844970, 0x29672044 }
        },
        // 65G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xFCDBB2B2, 0xDC2306EB, 0xBA66F4B9, 0x79527DB7, 0x7765765E, 0xBF639ED6, 0x06B6090A, 0x01628C47 },
                .y = { 0xB957B4A1, 0x66EB62F1, 0xBA659F46, 0x33CB7691, 0xF3E055D6, 0x2C90D98C, 0x2F174750, 0x7D096AC4 }
        },
        // 66G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC4CE250F, 0xC7C6E4D1, 0x44B81977, 0xA3CFA7FD, 0xE42F8CB2, 0x5A7E384D, 0xE3A7DE48, 0x78ED4FE6 },
                .y = { 0xE9E571CA, 0xA9231C8C, 0xD0F5BB2A, 0x55912064, 0x75554FAD, 0x9C03344B, 0x3E909DFB, 0xB1234799 }
        },
        // 67G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x51F9C391, 0x86F04D3B, 0xA48A4DDD, 0xC16D0C52, 0x891EA186, 0xFC88362A, 0x7DE96A54, 0xE8218AD0 },
                .y = { 0x2F33AF7A, 0x2C735AC1, 0x06620AE8, 0x05AF456A, 0xC30A96A0, 0xDE3EC728, 0x9A8F62D9, 0xFD59D7EB }
        },
        // 68G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x6A93954D, 0x8732D5CD, 0x0DD71FAB, 0xC35D34E7, 0xF99C55FE, 0xB2CDB039, 0xBB4A44B9, 0x031195D5 },
                .y = { 0x08A660C8, 0xBAA37F5D, 0x7B57DF81, 0xBB704734, 0xCE0F8C32, 0x440DEC9E, 0x400C9463, 0xF66904B1 }
        },
        // 69G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC5E79347, 0x9E5DA11C, 0x361BFE25, 0x87986A54, 0x91E9AE09, 0xC8568688, 0x548EFA2A, 0x49D3AD05 },
                .y = { 0xF4EB5CF6, 0x987B0687, 0x2655D14F, 0x9BEA0D0F, 0x3A8DD126, 0x2126AC55, 0x546FBECC, 0x6D37B1FA }
        },
        // 70G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xF58A379A, 0x7C5A2A14, 0x39F76B81, 0x7263DE15, 0x2B3A8C59, 0x681D690F, 0x78C04937, 0x100392DC },
                .y = { 0x5BEF953A, 0x07E5E8E8, 0xAD0182E4, 0xD11AE42D, 0x27C9A2EA, 0x9CC6E22A, 0xE6E2F3B1, 0xC6793AD2 }
        },
        // 71G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x92AA7864, 0xF19F382E, 0xFC05804B, 0x49C7CB94, 0x40750D01, 0xF94AA89B, 0x4A210364, 0xDD421B5D },
                .y = { 0x39DF3672, 0x56CD001E, 0xDD4AF1EC, 0x030A119F, 0x96CD0572, 0x11F947E6, 0x93786791, 0x574CC7B2 }
        },
        // 72G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x79C1E3B1, 0x73313696, 0xA360FB55, 0xB1EE4879, 0xF38FAE9C, 0xEB5D0C75, 0x15B15144, 0xC3B025A0 },
                .y = { 0x0DC40604, 0x33AD5354, 0x9C5D2E6A, 0x1BA0CB8C, 0x2E4283E1, 0x0368EB1F, 0x809A06F2, 0x6FCD0CBB }
        },
        // 73G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xEEB03D1A, 0xAE8F8FE1, 0x096FB852, 0x2B34A7DC, 0x17E29B1A, 0x794922EF, 0x6EF82FCE, 0xB2DACDF6 },
                .y = { 0xF42911EE, 0xDB8DCC81, 0xE405CA09, 0xB871BA63, 0x5E82D5B3, 0xA66D9252, 0x1AF82878, 0xC3972552 }
        },
        // 74G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xE25A441E, 0x46CE85A9, 0xCA1B04E0, 0x294B12E1, 0x5D34F708, 0xB00EEA8A, 0x35B23E27, 0xD176448E },
                .y = { 0x2BB80EF9, 0x5CE88539, 0xB3BFFFC8, 0x0C45E52D, 0x519978D1, 0x77C52D75, 0x2FA1BD2F, 0x0A48558F }
        },
        // 75G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xFB760095, 0x616D2C02, 0x2A7AA6AB, 0xCFA8CA0E, 0x23AF72E0, 0xF1237162, 0xA42FD1F6, 0xA22F8FBE },
                .y = { 0x78F3D040, 0x5072758B, 0xED4437A8, 0x7BE19F0D, 0x70456A7E, 0xE79807A7, 0xD0C2302D, 0x24A1BDE1 }
        },
        // 76G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC89BDD46, 0xCD331464, 0x21848F49, 0x285BED3C, 0xCD1823B4, 0x7C703717, 0x7EF5B48A, 0x1558FE4C },
                .y = { 0x50EAED5F, 0x19C66020, 0xD47FA3CB, 0x3FC6E661, 0x937E1BA3, 0xEE4826A9, 0x93B83E45, 0x9B3B0404 }
        },
        // 77G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC266F85C, 0x0A2193BF, 0x5A0EC9CE, 0x719A87BE, 0x2B2F9C49, 0x9C30C642, 0x3D5BAEB1, 0xDB15E496 },
                .y = { 0xE0D37321, 0x83C3139B, 0x2E9FDBB2, 0x4788522B, 0x77EB94EA, 0x2B4F0C78, 0x95105F9E, 0x854DC9D5 }
        },
        // 78G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xA6AB1ECF, 0xADE6AF11, 0x65013B3A, 0x7E966103, 0x7B5065A4, 0x711F8B7F, 0x97536F3F, 0xC0E78A38 },
                .y = { 0x464423D3, 0x48B4389C, 0xB2011371, 0x407BFFA1, 0xEF96B473, 0xEA2240CC, 0x8474D0C8, 0xF8BDF2EA }
        },
        // 79G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x30FF0E92, 0xA40206D3, 0x05176F8B, 0xDD306E2A, 0x65F89E14, 0x58F64281, 0xE89327FC, 0x5ED556AA },
                .y = { 0xF8321BB8, 0xC2B1870A, 0x99227B16, 0x097A54FF, 0x50128375, 0xD07370C4, 0x191A421F, 0xB75DF5EC }
        },
        // 80G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x52B3E584, 0x492BDC07, 0xB5F86A2C, 0x35FF9AA8, 0xB27DE573, 0x2074213D, 0x5263832A, 0xC0BFFFC4 },
                .y = { 0x1D49C605, 0x2429C22A, 0xB320EBFB, 0x1B037D75, 0x9220F428, 0x52B6A173, 0xA4CD2660, 0x2995919C }
        },
        // 81G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC63D5E79, 0xD3A5D81F, 0x02BA3183, 0x8E9D0AF4, 0x165C6E4C, 0xB097C711, 0xEBFF18D3, 0xE0BEEB1A },
                .y = { 0x0801937B, 0xFE657F13, 0x6FE5B29D, 0xA02DBC42, 0xCF290D1F, 0xCBDBFDB9, 0xE85BC145, 0x7ACF4419 }
        },
        // 82G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xAD29CF9C, 0x80EE662F, 0x25A81AEF, 0x59D18BE9, 0x75274655, 0xB932D0C1, 0x554FA366, 0x8D97FD53 },
                .y = { 0xCD789D17, 0xAD5CB247, 0xE93046F2, 0x41A471E4, 0x18FB05AE, 0x49761263, 0xDEF3F99D, 0x18F61F3C }
        },
        // 83G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC3363A22, 0x2C9EE62D, 0xEC67199A, 0x125D4714, 0x2AB80485, 0xF87ABEBF, 0x7A243CA4, 0xCF3086E8 },
                .y = { 0xC64E09DD, 0x5C52B051, 0x5625AAD7, 0x5E9B1612, 0xB19C6126, 0x0536A39D, 0x47B64BE5, 0x97F00132 }
        },
        // 84G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x43020EEC, 0xB7F1695A, 0x941A27E9, 0x2CD0BAB9, 0x811A47EB, 0x10B429A2, 0xCA881F6C, 0x2F83A889 },
                .y = { 0xF683E890, 0x2563C590, 0x2E45CBB1, 0x67F9BA80, 0x1B99EC5F, 0xDF4741A7, 0xB6F36034, 0x4CB3C135 }
        },
        // 85G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x7E1EE314, 0x3646B0DD, 0x25AF7677, 0xEF617E00, 0xEA65641A, 0x36BF2F65, 0xB5E11EFF, 0xABFC8457 },
                .y = { 0x8F1192B6, 0x998DFAC1, 0x0142811B, 0xCE91EE27, 0x1F282369, 0xBB0066AE, 0xE1CBAEBE, 0x159751E2 }
        },
        // 86G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x42A18DC1, 0xDD5C2B81, 0x744A6528, 0x783B9BA6, 0x0B4AF06E, 0x23FB7427, 0xF80E4B90, 0xA9EA1B80 },
                .y = { 0xEDCA6F38, 0x559759F6, 0x7DEFE51B, 0x4A2B5ED5, 0xE8AEAF7D, 0x9A9F04F0, 0xCEFDB61D, 0xE6C93B31 }
        },
        // 87G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x7B4D8B2C, 0x516329FF, 0x2D4B409B, 0xB856664A, 0x7F6B0670, 0x04125299, 0x60826CAA, 0x2BD02043 },
                .y = { 0x61DDBCB1, 0x010E5226, 0xC235D56C, 0xCD07BC34, 0x06E58E3E, 0xA8F439AB, 0xD5CFF157, 0xAF490825 }
        },
        // 88G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x8418CAE4, 0x7D81FD48, 0x369A6067, 0xABEEE3E9, 0xB939F40F, 0x1707165B, 0x6932E631, 0x948FB3F7 },
                .y = { 0xEABD468E, 0x005A1DFF, 0x8C7F9DBA, 0xBDF17610, 0xC911847C, 0xED5CF82D, 0x2785971D, 0xD8D37D94 }
        },
        // 89G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xA7EABE67, 0xC1EE6264, 0xFD54487D, 0x62D51E29, 0x6310EB5A, 0x3EA12344, 0x4765B805, 0xBD88ACA7 },
                .y = { 0x14FB691A, 0xB7B284BE, 0x3B9FFFEF, 0x640388F8, 0x09F98F9A, 0x7AB49DD2, 0x7211E445, 0x7150F87E }
        },
        // 90G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xDE992E6E, 0x9AF9D782, 0x83E90446, 0x47305B74, 0xD7EE64B7, 0xF3DF44DE, 0x55648A4C, 0x8307D5CB },
                .y = { 0xE277280A, 0x5376B018, 0x25D3FDEE, 0xABFF56B5, 0x1C309A59, 0xAD3294FB, 0x49C0B6A1, 0xE485B90D }
        },
        // 91G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x6982F865, 0xD81AD938, 0xAE6A94B8, 0x27113BB4, 0xBEDD4F47, 0x4A39F02B, 0xD5692705, 0x0211DE8F },
                .y = { 0x63C92F69, 0xD587138C, 0x6237FC68, 0x2354719F, 0x0B46A59F, 0xFA8A5B9B, 0x5C554ED3, 0x4A70ABF7 }
        },
        // 92G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x6294BA47, 0x9D7127D7, 0x1487C526, 0xA8A38BC3, 0x39093801, 0xE4C84178, 0x43AE4336, 0xAEE309E5 },
                .y = { 0x9359250D, 0xD4B12739, 0x8F48BB12, 0x9929AD4E, 0x7F73442A, 0x4A72075D, 0x2FAAB294, 0xD1542859 }
        },
        // 93G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD9453D29, 0x64CFDC70, 0xFD36B1AF, 0x0AEACA9A, 0xE1639607, 0x4A278686, 0x1FDF2498, 0x0581B471 },
                .y = { 0x3D61F6D2, 0x82290E25, 0xDF219DC5, 0x20B021C3, 0xF9A2852F, 0xFF6C1A78, 0x954FFBB3, 0x435AC466 }
        },
        // 94G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD2DF5E7A, 0xC82A7AEF, 0xD59848EB, 0x955EF205, 0x03D41796, 0xC87BDB82, 0x037278D9, 0xBF87EA83 },
                .y = { 0x8719AEA8, 0xC5825A63, 0x64135771, 0xC00286D9, 0xDFA99607, 0xF8EA79EA, 0xDD85AA7B, 0x1001F8D7 }
        },
        // 95G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xB308CC40, 0x263E039B, 0x2B346FD2, 0x6684AD76, 0xCAA12D0D, 0x9A127F2B, 0xA974291F, 0x76A8F9FE },
                .y = { 0x68AA19E4, 0xC802049B, 0x0C5DBBA0, 0x65499C99, 0x344455A1, 0xEE1B1CB5, 0x2CD6F439, 0x3F293FDA }
        },
        // 96G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x33E12B70, 0x802B8D23, 0x19DD329B, 0x6D490A4B, 0x6ABC354D, 0x14F356CC, 0xD0A0DA0D, 0x11EDDF7F },
                .y = { 0xD87FD1D8, 0x1E208328, 0xFD025813, 0xFD2F4F8C, 0x7C29BCA2, 0x03B48CC4, 0x241A2B71, 0x3F2A78B3 }
        },
        // 97G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xAFCEB64D, 0xDC90323B, 0x397E43F4, 0xDA8CDB78, 0x2566805E, 0xEE848E1D, 0x578181C7, 0xF1AE5380 },
                .y = { 0x9C70C77C, 0x2DC7B8E6, 0x5B68B7E7, 0x85F4D9C4, 0x3260B767, 0x84577F1F, 0x53CF3E69, 0x1FBD470F }
        },
        // 98G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x589B69FF, 0xD5192C88, 0xBC82A095, 0xCC8715AB, 0xEE3751BE, 0x74B44206, 0x8794885E, 0xA6EECF30 },
                .y = { 0xDD0CE3B4, 0xA05A7AA8, 0xDAA4C864, 0xA3F98377, 0xE390DA5B, 0x6B5DF55F, 0x24C2E311, 0xE9F04CD3 }
        },
        // 99G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x3F9432B4, 0x2D037BF8, 0x6A7B4371, 0xB1F1ABB6, 0x4A9A3B17, 0x650522FD, 0xA4E65B07, 0xBC438AE1 },
                .y = { 0x84693C04, 0x31B57EA2, 0x75503E46, 0x7AB58A3F, 0xB98FF4B3, 0x03A3C2C7, 0x54FCD65A, 0x4A673FE0 }
        },
        // 100G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xBF61FEC5, 0xB9A17DB9, 0x61C52CF8, 0xFE492331, 0x3FE90A2F, 0xF7AC4673, 0xEB1385F3, 0x55401274 },
                .y = { 0x23FD068F, 0xA5DB852C, 0x85BAC6B7, 0xADB9E9B6, 0x30548CF4, 0x6AA068C2, 0xA1715422, 0x63BE9E64 }
        },
        // 101G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x4EA6FDF7, 0xB7A96E0A, 0xB99CD026, 0xBBE914D3, 0xC569A602, 0x6A610374, 0x14DA499E, 0xE9B1C239 },
                .y = { 0xADC19A99, 0xB5F6F0FE, 0x6F21687C, 0x73125182, 0x4BE77793, 0x5A8A1464, 0xDBA8BFC7, 0x94CE9E0A }
        },
        // 102G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x8F9B4748, 0x41A6FE76, 0xE9F60F18, 0xF5284782, 0xDD3DAC5C, 0xCE33E49C, 0xFECF6FED, 0x0FCAEC0F },
                .y = { 0xA54EDFC4, 0xCA1CE130, 0x5BC92AA3, 0x6445FBCD, 0x20FE78E3, 0xF3D348F8, 0x8417C98F, 0xA2776D9F }
        },
        // 103G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC71F8D02, 0x564BDDA6, 0x19F7F72C, 0xD0A875E9, 0xBF619241, 0x57670E41, 0x4C3C386F, 0xF51EC872 },
                .y = { 0xE8BF7D17, 0x00AEC19E, 0x286166F3, 0x5DF79360, 0x30A4F924, 0xA6FAE609, 0xAE1D3ED8, 0x1429B1F8 }
        },
        // 104G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x82C4BD6A, 0x82D00206, 0x4C2A6235, 0x90EE4655, 0xC7AC3EFA, 0x35D2293F, 0x734FC1B8, 0x1D6DE36B },
                .y = { 0xCFF75858, 0x946AC3BF, 0x61217DEE, 0xFFCCF5E1, 0x77B9D084, 0x75AEF88A, 0xDE5A0CC1, 0x6BA92BCA }
        },
        // 105G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x7B371390, 0xDE6DDCB7, 0x02A9BA44, 0xCB11125C, 0x2B1D28FD, 0xC08EC160, 0x65E03A86, 0x680D5ABF },
                .y = { 0xF5327839, 0xD5EC7BBB, 0x3BCE7FE5, 0xC87057CA, 0x71CBFC97, 0x4E346DB0, 0xEE9E512F, 0xD3D6D111 }
        },
        // 106G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x1E628B51, 0xC4C398CC, 0xC098AEFA, 0x750C11BB, 0x279DF6FF, 0xB81F9FB1, 0xFF1765EC, 0x7145405D },
                .y = { 0x83AAE16F, 0x3C3D861D, 0x7BC27EF7, 0x13721825, 0x03FE8FAC, 0x5CBB069B, 0x0757AAEA, 0x262F03EB }
        },
        // 107G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x3796F4C7, 0x2CA0BA9C, 0x592CE334, 0x3571E4D1, 0xE9F6E877, 0x28F9CDEB, 0xEFCE1A70, 0xEE206023 },
                .y = { 0xB76369DC, 0xB2159E08, 0x0A7F687C, 0x2754E426, 0x02DE2FF1, 0xE008039E, 0x8EA700C1, 0xCCD7E941 }
        },
        // 108G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x72371E17, 0x2871263F, 0x4D7DF1FF, 0x14D14798, 0x42E1CBF4, 0xD1A86787, 0x000A079B, 0x9D873705 },
                .y = { 0xE01FFE00, 0x3A7F4AD5, 0x70094E6A, 0x3633966C, 0xB13E2B49, 0x08E545F1, 0x4B5D416D, 0x0D66CFC9 }
        },
        // 109G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xDD10EDD0, 0xAEC63ACB, 0x91AE8D13, 0xFD4F61E4, 0x4DF861F4, 0xE7B09217, 0x5548DE20, 0x3720B247 },
                .y = { 0xEBF3DF78, 0xAF419847, 0x56CD660D, 0xE7229D89, 0xEB879899, 0x0CD622BA, 0x1CAB12C7, 0x5FDAEE39 }
        },
        // 110G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xA463FBAD, 0x76FBEDB5, 0x23FBBE6E, 0xB1FC8C8C, 0x39DCAB99, 0x45AE78BA, 0x652405A9, 0xE7009EE6 },
                .y = { 0x8C0531E8, 0xB9A8FC5F, 0x7F000956, 0x5761490F, 0x6E4840F1, 0x270C706C, 0x4EF37E3C, 0x798CA99E }
        },
        // 111G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x86653AA8, 0xD87F4AE0, 0x8072F08D, 0x327DAC31, 0x0832C416, 0x098F37BB, 0x7A9B6A20, 0x0CF804D7 },
                .y = { 0xA67E2173, 0x4B9C5438, 0xA23AFA67, 0x1CC0D4CE, 0x7148B135, 0x270ADCC5, 0x904D4731, 0xF9AF0ACD }
        },
        // 112G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x0A99CBCA, 0x6A950576, 0x04A428F2, 0x94E258F6, 0x7832BA0C, 0x45AB5A4D, 0x8938C167, 0x71704D00 },
                .y = { 0xF88B8B70, 0xDB97AB0E, 0xC00EB207, 0x56FEB92E, 0x7D367D80, 0xE7035268, 0xC7973A41, 0x65000C24 }
        },
        // 113G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xB7EBCB88, 0xA125E6C1, 0x10EC0D40, 0x3289E86E, 0x98353869, 0xCC3A5ECB, 0x8A2B0D3A, 0x734E0D07 },
                .y = { 0x51933360, 0xE0D92E9A, 0x786076B9, 0xFA6BCDB1, 0x747F19EC, 0xD13CCA90, 0x49F3A53D, 0x61D8209D }
        },
        // 114G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x216F7C55, 0x751E03F0, 0xBC30D62C, 0x18849F8E, 0x9B4E920C, 0x7AFEC8BB, 0xF216DC99, 0x08E2F429 },
                .y = { 0x1D6CC33E, 0x5E5DDF82, 0x4D7BF847, 0x97B596A1, 0x0A9F8671, 0x96B98414, 0x924DD154, 0xBC0EEC86 }
        },
        // 115G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x119F6CAB, 0xAD19E039, 0xA8DFCE56, 0xF15B920F, 0x851B5BC7, 0x8A2627C4, 0xD8ECCA6E, 0x7C3FF661 },
                .y = { 0xD5F5B5BF, 0xB9DD2BF2, 0xBAA43B27, 0x56B76C57, 0xFE2F4937, 0xDC8DF855, 0x889821B2, 0xE95DD9D8 }
        },
        // 116G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC9826344, 0x87F9793B, 0xB2F5F79C, 0x4B3DE89B, 0x59CB1B6E, 0xC9F08A56, 0x6A92B9AA, 0xD8F1FC5F },
                .y = { 0xB412595E, 0x86357F9E, 0x65B80F16, 0x53C30BBE, 0x70549A57, 0xF06C2C8C, 0x2B9157DA, 0xA9C8A4B4 }
        },
        // 117G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x1B620DC4, 0x08E4C490, 0xD9699E92, 0x55A3BB1A, 0x47968833, 0x7890E8D5, 0x79AF29B1, 0xBBDBEC7D },
                .y = { 0x3E51E1BC, 0x92750DE7, 0xAD91A350, 0x50CF6D11, 0xFA67285C, 0x9DC33392, 0x4480FFE3, 0x2CDF7F85 }
        },
        // 118G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x3F5F68A6, 0x24C00DE9, 0x5512EC1C, 0xF8F1D841, 0xBB07AD54, 0x24869D65, 0x54D7A19E, 0x49773796 },
                .y = { 0xF061CEDE, 0x04F357D1, 0x03BC88E6, 0x741BF80A, 0xC527A656, 0x6CF96715, 0x98E59B62, 0xC9C4D639 }
        },
        // 119G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x6CC47305, 0x87AF199E, 0x1E314DDE, 0x062AFB7C, 0xF3A49FB4, 0x2BE22BA0, 0x157B7F56, 0x6ED0B988 },
                .y = { 0x2D653FD9, 0x8162CF50, 0x877B7497, 0x17D29C64, 0x0F67B514, 0xD7E81438, 0xFE6EE703, 0xFEDF1014 }
        },
        // 120G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD0303BA4, 0x6EBDB7BC, 0x4F6AB73A, 0x094E7DDF, 0x37E7454E, 0xB62AAF7C, 0x45A2473F, 0x9C7EA212 },
                .y = { 0x9488D036, 0xCA76E754, 0xAAA03497, 0x9A278A9D, 0x2C1EB541, 0x48CD158B, 0xA47A7152, 0xD007EC78 }
        },
        // 121G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x8C03E3F4, 0x14D7251A, 0xB0E5FE20, 0xD71602D5, 0x683B30D1, 0x27D2BF4F, 0xF77F10E1, 0xE1A8D418 },
                .y = { 0x76A0EAD7, 0xA4941A1E, 0xDA0A4996, 0xFF318484, 0x93394872, 0xAAF4D4E1, 0x0E99505C, 0xAE839CD8 }
        },
        // 122G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x2F4FF97A, 0x536EEEA9, 0xCAF64CBD, 0xD183A961, 0x9358983A, 0xBF357E0C, 0x573FBFA8, 0x62280F9A },
                .y = { 0x7E9176B3, 0x001DA1B7, 0xB1901D3D, 0x6EA945BD, 0xBD51F905, 0x4C6B9954, 0xB2A104B2, 0x7AA3B3CC }
        },
        // 123G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x03B58B02, 0x62EA8598, 0x98A5EA8C, 0x5A714971, 0x917E4725, 0x1783D1B6, 0xF1E35487, 0x2D7CA4D8 },
                .y = { 0x9B4D4324, 0x3F69B4D4, 0x8E17FF54, 0xDA04CC89, 0x16E3E02A, 0x5870726C, 0x69E788C5, 0xAEB9041C }
        },
        // 124G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x85FC00A2, 0x10F264BC, 0x76D7996D, 0x0A10ED15, 0x7F141275, 0x49B1DFCA, 0x56DB1266, 0xD8C04721 },
                .y = { 0xCD768437, 0x43DFABF3, 0xE4DD905A, 0x58D85051, 0x4C99E439, 0x9B94C4AD, 0x901289FE, 0x8448ECAE }
        },
        // 125G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x93740130, 0xAAB54CFC, 0x225733FA, 0xF72DAB6D, 0x1ED32559, 0x04B76D2D, 0xBB85B9CB, 0xA9FE2396 },
                .y = { 0xBF2219F0, 0x128B0D24, 0x579F3CE2, 0x2292393B, 0x145FF0D5, 0x51DC5FAC, 0xC3FEBBC1, 0xB16D6AF8 }
        },
        // 126G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x52BF127A, 0x9C9635BE, 0x807A9D28, 0x519A47B4, 0x60AB52E9, 0x9A7D7036, 0x752838C3, 0x6941195B },
                .y = { 0x70DA613F, 0x60FFBE2E, 0x52761718, 0x8459F570, 0xAA36DE2D, 0x5F153F56, 0x215215F6, 0x91A4EA6D }
        },
        // 127G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xDEE35B41, 0x36E84BB6, 0xDDDFD928, 0x70E9016C, 0xAE619F28, 0x6072A061, 0x904A36CF, 0x15FE6A86 },
                .y = { 0xF6005965, 0x9AB6968B, 0x0AD602D0, 0xFD1C4A97, 0x44F403F2, 0xD0A88792, 0xABE3C14B, 0x76759223 }
        },
        // 128G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x7A2AD62A, 0x63C5CB81, 0xAC62FF54, 0x7EF2B6B9, 0xB3AD9DB5, 0x3749BBA4, 0x46D5A617, 0xAD311F2C },
                .y = { 0xC2FF3B6D, 0xB77A8087, 0x367834FF, 0xB46FEAF3, 0x75D6B138, 0xF8AA266D, 0xEC008188, 0xFA38D320 }
        },
        // 129G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x89A6B23C, 0x45D8FADF, 0x6FFFBBFE, 0x057DEE06, 0x4774E5E2, 0x6DD5757B, 0x47607091, 0xB44267FA },
                .y = { 0xAC739807, 0xD254AC6F, 0xE4097EAC, 0xB29BEA93, 0xCE2B1765, 0xDE07A886, 0x6561E516, 0xA326800A }
        },
        // 130G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x1E379D0A, 0x9967CB4A, 0xE1E6ADD9, 0x7A6357D9, 0x779E6CAC, 0xCA3974E8, 0x856196F0, 0x2F169029 },
                .y = { 0x0F737805, 0xE004869E, 0x1EFEF15F, 0x07F284A3, 0x6588EAD4, 0x46102B44, 0xCBD1DC45, 0x0F28B78F }
        },
        // 131G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xEE931637, 0x44359AC0, 0xBEF60C41, 0xD7AF3AC7, 0x5C9A5A00, 0xD451E48E, 0xDE205114, 0x879A858E },
                .y = { 0x5CFD0B21, 0xD3234506, 0x794A5062, 0x4D7BEA68, 0x29FC3993, 0xA4F7B9D7, 0x4E5EA446, 0xE838260E }
        },
        // 132G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x5A8F896B, 0xD27EDF79, 0x5A852846, 0xE7CF9E5D, 0x9B86FD86, 0xBA5BE7BD, 0x729FF5C6, 0xC1E44A11 },
                .y = { 0x1E2649A6, 0x07CA3E3A, 0x85096F79, 0x0031203B, 0x6ABC2BB3, 0xE1DD0702, 0xD48CFA00, 0x06D58594 }
        },
        // 133G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xE4D4B063, 0x97484C32, 0x6873506E, 0xBB397E44, 0xE0C682B4, 0x233F2018, 0x68D12590, 0xFF6BCBC9 },
                .y = { 0x2357E496, 0x97F470FD, 0xBCB4B614, 0x5C523069, 0xEA506661, 0xEA33B10E, 0x04B09A83, 0xC1F96DDF }
        },
        // 134G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xB28239B9, 0xB4E88695, 0x7E74BD40, 0x8C587AC2, 0xBCA8727A, 0x36D0F005, 0x7464FBF0, 0x3632AA73 },
                .y = { 0x9B369F08, 0x568ED633, 0xC4881E96, 0x1D89E750, 0x1BCCEC2D, 0x41A2B414, 0xEC598B6C, 0xB961F44A }
        },
        // 135G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC45E9796, 0x9E57D734, 0x1AB41BF5, 0x153BE80D, 0x55031CAA, 0xA3E0C365, 0xA3294D40, 0x52CF34EB },
                .y = { 0xFF583EBF, 0x17832C7D, 0x66E40FAA, 0xAAF70368, 0x7F4B0FA6, 0x19FFE1C8, 0x9A663404, 0xACB5D3BD }
        },
        // 136G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xCDBB159E, 0x333F6134, 0xC814272A, 0x7AABFEA0, 0x7D57774F, 0xDE5A0A9A, 0x4303F9F2, 0x480136CA },
                .y = { 0x546954E0, 0x78C8EE22, 0x301BED93, 0xBA7407AC, 0xC4FEFB70, 0xC21A6ECD, 0xAB9D97C1, 0xBB968B77 }
        },
        // 137G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x72D4ED33, 0xB7FECB5E, 0x5165F53A, 0x20A22A80, 0x9E158E90, 0x2CC11D87, 0xBA2CCE03, 0x9E9CBA4D },
                .y = { 0xA018C44B, 0x1BBE8B81, 0x20BD77A8, 0xBC42FEBD, 0x9CEA765F, 0x952B4D83, 0x58C0DBE7, 0x64E52943 }
        },
        // 138G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x6B14F752, 0x6224906B, 0x96BB1EE8, 0xED60E718, 0x95B038D9, 0x55A6C464, 0xCA840638, 0x5FE4AFC1 },
                .y = { 0x303C71E2, 0x45959D48, 0xB56967E2, 0x946BF974, 0x9B2DF1C4, 0x23081089, 0x6720AA3F, 0x84DE5346 }
        },
        // 139G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x09B785F9, 0x123CD8A5, 0x1EDD29CD, 0x85640251, 0x66E9882A, 0xB60E95AC, 0x0F43CAAA, 0xF9107EC9 },
                .y = { 0x8B6601DF, 0x8F48FBB9, 0x1CEB4B35, 0x3AFDD0F1, 0xF470CEEC, 0x0A804B08, 0xB33D1017, 0x04310217 }
        },
        // 140G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x3267400B, 0x80DE24B5, 0x1FF15B83, 0xD8330643, 0x902DD58B, 0x8A426D98, 0xEBAB3F60, 0x14B9F481 },
                .y = { 0xF3497FE8, 0x5B1872C0, 0x56963F5B, 0xA6474C98, 0x43EAE2D8, 0xE787E995, 0xA193C1AE, 0x7FD49E25 }
        },
        // 141G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x04954B44, 0xE7319A16, 0xC154A104, 0x039C1B75, 0x5A470317, 0x58A55700, 0x15E86AF3, 0xD3608E5E },
                .y = { 0x5925D28D, 0x865B9C5B, 0x2887E5EB, 0x92F3BDEB, 0x646BFA23, 0x9AD29E49, 0xE2C90EAC, 0x1ABF07CA }
        },
        // 142G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xF9B5F27B, 0xA86165F4, 0x659BFBC6, 0x4BD4962B, 0x83F9AC63, 0x4E33B3C7, 0x4EB82E67, 0x0D2E7879 },
                .y = { 0xA00989F7, 0xB02CAC9D, 0x43247E6D, 0xB61A26DB, 0xDB9165B4, 0x79A28B2F, 0x7B74CC84, 0x8F2667FD }
        },
        // 143G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xFEEE0D22, 0x3F21DACB, 0x2867812F, 0x38CC5A16, 0x863B12D5, 0xFB482BB8, 0xB417B0F3, 0x4838F777 },
                .y = { 0x5403B490, 0xD0A0163F, 0x6E3636A5, 0xFED78398, 0xC8164FAA, 0xFED128B6, 0x4FF653A7, 0xBC091680 }
        },
        // 144G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x58654FEB, 0x11BA0B81, 0xC40973C6, 0x83D0C099, 0xC0AF37CE, 0x4ABB178B, 0xBD1662AB, 0x18B621E8 },
                .y = { 0xDB878B55, 0x77F15C29, 0x1BC0B40F, 0x8716F078, 0x5A27182C, 0x475F0507, 0x6C77B89E, 0xC039BAB4 }
        },
        // 145G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xFE873080, 0x99AF5CFE, 0x17EDEAF0, 0xBB41A9B5, 0xAC761EA1, 0x6448D7BD, 0x2219AF0A, 0xCA5DC1A0 },
                .y = { 0x0BA7DF53, 0x7508B4D1, 0xE51252D8, 0x4186F17A, 0xAE9A0019, 0x009FFD7C, 0x6B32112D, 0x52DE55F8 }
        },
        // 146G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x5E19934D, 0x3E2AF477, 0xCCD90157, 0xA1360D72, 0xA7A2008C, 0x145E370E, 0xF7A42942, 0x8880D5D3 },
                .y = { 0xD7F845B9, 0x0245B7E1, 0x36928871, 0xF92A24EE, 0x23E0E22B, 0xB3E4BF85, 0x30F55150, 0xDDD7519A }
        },
        // 147G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xBB31FE40, 0xCAB32D59, 0x3893EC5B, 0x875CF0F5, 0xA3D14ECC, 0x41A4D820, 0x7BB6F782, 0xCC302373 },
                .y = { 0x82E13276, 0xF40F9FAA, 0x8A75C2A6, 0x207DE89E, 0x9D371C05, 0xA3F2483C, 0xC8588F2A, 0x7D5C6592 }
        },
        // 148G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x576F99A4, 0xD6210031, 0x163B9D63, 0xD7E7154B, 0xCF47E0A3, 0x9133C728, 0x7B813E6C, 0xD1CFDD45 },
                .y = { 0x3621E569, 0xAA0D60CC, 0x06FCA960, 0x4C5C914A, 0x28300A54, 0xA915B0F0, 0x9D1BE2C0, 0xE483BF7C }
        },
        // 149G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xB7C5AE8A, 0xBFAD3818, 0xDB8AD0A0, 0xEFC278A4, 0x159B6E9F, 0x43B83BD7, 0x6096551D, 0x0D6905D5 },
                .y = { 0x323069EF, 0xF73CAB34, 0x6EADA798, 0x80F4AD4B, 0xEF04AD92, 0x3893D4A8, 0xDC7E0D78, 0xA62CFC3F }
        },
        // 150G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xF0D324E2, 0x7CCC0558, 0xDC381B1D, 0x6BB494BC, 0xADE8BC7A, 0xFB0D5D57, 0x9594ADCB, 0x9D644BDC },
                .y = { 0x365A23A1, 0xC17EC5D5, 0x6B520566, 0xFD25DF3A, 0x6956821D, 0xEAFFF798, 0xD9F20EB3, 0xE74029AF }
        },
        // 151G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x00D22061, 0x02B8AB75, 0x00267F28, 0x6FC8292B, 0xB43D01F6, 0x892717D7, 0xDEAB769A, 0x0DB84B08 },
                .y = { 0x3341E324, 0x7BCE6E25, 0x0AED2186, 0x8498B313, 0x1E3A8B1E, 0x3C3E759E, 0x49E8ECD3, 0x413EF0E8 }
        },
        // 152G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xB3FB1E8B, 0xCB481253, 0x8E0BB160, 0xD36F9A07, 0x58DF0E0F, 0xE2B2EDFC, 0x179F3B33, 0x283A6FE7 },
                .y = { 0xFCA3E014, 0xEB1A54D3, 0xBA72B5F7, 0xFF712727, 0x31675D87, 0x5C7DB043, 0x27799B86, 0x05D30E76 }
        },
        // 153G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xE1B0D9F5, 0x45922AED, 0x1D52C62F, 0xE3CEC601, 0xD2CC8869, 0xD9140C37, 0x83FE435E, 0xDEAC1E25 },
                .y = { 0xD5065970, 0xA7F219A5, 0xF6EAC893, 0x14BFD6E7, 0x87259935, 0x1C65B6CF, 0x4409735C, 0xF1F81562 }
        },
        // 154G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xB64AFDE2, 0x67C8850E, 0x1B1F6BDF, 0x04539163, 0xF8850C28, 0xC9C5E91A, 0xA1107CEC, 0x2FFE68B6 },
                .y = { 0xF506E874, 0xE6BEDBD9, 0x139006C3, 0xAD3ED26B, 0x8ACC335D, 0xCFC0DA90, 0xA4F8E30D, 0xAF02C98B }
        },
        // 155G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xE31AB219, 0xA8D342DE, 0x231B83B7, 0x58E56C31, 0x357F517D, 0x588A5AC5, 0x1FA78892, 0x9FE3ED11 },
                .y = { 0x3A299F46, 0x7CE350B9, 0xD96EA7B6, 0xB200D300, 0xA2ED141B, 0x13535F43, 0x7335DC58, 0x54598B74 }
        },
        // 156G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xF0DF4EAE, 0x15F1AC7D, 0xA4EBE0F6, 0x8BD3EF7E, 0xC3B629D9, 0xC2090442, 0xA53686DB, 0x7A913332 },
                .y = { 0x0983407D, 0x527F36AC, 0xE7EF13C8, 0xBA7959D1, 0x6265B3C3, 0x3140D4B4, 0x0310FB0C, 0xDE151409 }
        },
        // 157G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xFAE06EBC, 0xA5CF2F53, 0x989E4964, 0x03E53EC1, 0xCBE3F981, 0xCF850164, 0xB29B5A09, 0x3790D90A },
                .y = { 0x032F0751, 0xFBDFBA2C, 0xDFAB2EC6, 0xA7614B52, 0xE4812729, 0x0D6285A1, 0xAA964C7A, 0x77117650 }
        },
        // 158G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xBFC9AF44, 0x8FD27479, 0x487A7D3F, 0xE7486D10, 0xF999C0C9, 0x0984C449, 0xC8E2629D, 0x4F9F8F19 },
                .y = { 0xFAC5D030, 0x5C5DBC17, 0x1422B6EE, 0x182CB40B, 0x5790637B, 0xC46AC7E9, 0x7BB90B9B, 0xF58AFA57 }
        },
        // 159G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xEB6F06D6, 0x7370CDCF, 0x05B860E0, 0x44AED8C5, 0x955CE458, 0x6FDD5F8A, 0x6C25882D, 0xC902D5CB },
                .y = { 0xCFE28F37, 0xA8A4EC69, 0x2B44FF84, 0x5E025CD9, 0x83B3F249, 0xBCFE87D2, 0xF9E8DCE7, 0xEF54E3FC }
        },
        // 160G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xE3451A09, 0xC04AFA1A, 0xBC117423, 0x7CC69103, 0x51CF56EE, 0x876BE3AA, 0xAD844A25, 0xE7577D57 },
                .y = { 0xDB77F341, 0x266FED8C, 0x23AE4A2A, 0xCFA258DC, 0xDA782760, 0x53A7A98C, 0xCEAF7D4A, 0x04B48868 }
        },
        // 161G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xE4A7DE45, 0xDE2E3B75, 0xE031EC7D, 0x43064B46, 0x15C4E268, 0x1E4D655A, 0x09CDC5EC, 0x45F8A639 },
                .y = { 0xC2FA2CB9, 0xF66F0C9C, 0x5A6A27C2, 0xF3F67CF9, 0xC64E6EAF, 0x79FF7C51, 0x128766B5, 0x13A4FB3A }
        },
        // 162G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x54F65044, 0x30159050, 0x81D9F534, 0xA1A14F96, 0x8B92280A, 0x78B31009, 0xB313DECF, 0x09DD6BFE },
                .y = { 0x0B2E14E9, 0x8F5C6FB9, 0x5D5957CE, 0x031F529A, 0x27BA574F, 0x43D862AD, 0xE0FBADAC, 0x68AF0029 }
        },
        // 163G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x562BA952, 0x7C112439, 0x31D0A8CE, 0xD4A7DAD4, 0x77F1B401, 0x6CBE1392, 0xD4BD470D, 0x8D8A8907 },
                .y = { 0x727866CE, 0x8224FA8F, 0xA34A7265, 0x3FB96A11, 0xBAF2A7A4, 0x9F872EAD, 0x3FD22F28, 0x2734A68E }
        },
        // 164G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xF94DB96E, 0xCD4C1DB9, 0x68FB644D, 0x8FD5AF5A, 0x9062F6B4, 0x58631366, 0xB1EFB9EF, 0x2CED07C4 },
                .y = { 0x4152C92B, 0x9D66FA73, 0x1268ECA6, 0x58AAF8B1, 0x86E33532, 0xD2B86F21, 0x8F8484D9, 0x86CBA00E }
        },
        // 165G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xBCC86AD2, 0xE91BAB76, 0x9C9CEF95, 0xA5403F8B, 0x8F067D12, 0xB963D4F3, 0x0D2793F6, 0x5EFA9E0F },
                .y = { 0xA76E5E25, 0x86B23BA8, 0x3AFFC453, 0xB15BD9E0, 0x5776542F, 0xF6C0AD80, 0x145DC30F, 0x25D026E4 }
        },
        // 166G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x343CD6D1, 0xAAF4C806, 0x100EDF93, 0x84A7C5B2, 0x32FEFC3D, 0x89AE0FA0, 0x4B5E827C, 0xB3626341 },
                .y = { 0xB3F435F0, 0xE7BC798E, 0x26434F7E, 0xCE72303E, 0xB78DD3C7, 0xA39F4BD9, 0xF87E88EB, 0x9EF08279 }
        },
        // 167G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x0752E7C6, 0x25D4D5B5, 0x25AE272B, 0xC3C9DFB3, 0x1BC27C04, 0x480012DA, 0xABD77D0F, 0xCAEFFF38 },
                .y = { 0xBF975ACB, 0x95294FF5, 0x3BD5F9B9, 0xDA28F690, 0x489DCA02, 0x13E62404, 0x7E92271E, 0x9EF2C491 }
        },
        // 168G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xBC872BB2, 0xADB6A52F, 0x08B8F1EC, 0xF07AE025, 0x9D6E5CB1, 0x1EBFC86C, 0x29777D4D, 0x6C7F3AA1 },
                .y = { 0xB1AFED8D, 0x229815FF, 0x77057E03, 0x3DCC8024, 0xC6D0BAA2, 0x79C323A4, 0x7AE6F52D, 0x1A5091EE }
        },
        // 169G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xCDE85D86, 0x4C642278, 0x84AF5D69, 0x29CAC5DA, 0x9FF7A057, 0x2CBF3BEA, 0x05A3ED0D, 0x3CCF314E },
                .y = { 0x483911E2, 0x4A2CDBC7, 0x5F0A60E7, 0xD3920215, 0x1A2DE65B, 0x4EFF5A87, 0xE4F3D2A1, 0x9D3A9565 }
        },
        // 170G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xFC72E688, 0x5B193E1F, 0x54A3D1FA, 0x44A6A8B4, 0x2C7EBE4C, 0x639F7631, 0xC1F93A37, 0x1649CDD6 },
                .y = { 0xA334494C, 0x3464C93D, 0x5E505E25, 0xB20AFE65, 0x22146B93, 0xC159B1E7, 0x449AC9A3, 0xA1778F20 }
        },
        // 171G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xF43DDDCB, 0x4A2E77A8, 0x800A4B6B, 0xEB62EC3F, 0xFD357099, 0xF99C4406, 0x7948E690, 0x293394D3 },
                .y = { 0x66F61B38, 0xBA27DD74, 0x492B02F9, 0xA5B23D71, 0x3ED6BBD2, 0x1C98D594, 0x9E46561C, 0xEC0D4302 }
        },
        // 172G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC55F1F8C, 0x6629D7F2, 0x59F69E2D, 0x63903BB5, 0xB407B541, 0xDCE26A8D, 0x143FDFCA, 0x44A30507 },
                .y = { 0x888CCD77, 0xB78C6A3A, 0x68303B6C, 0x6F388CF9, 0x74177DA0, 0xEEACE5B7, 0xDF211DD1, 0xC8E7F75C }
        },
        // 173G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x72F86362, 0xE4E632A4, 0x0157EB61, 0x1B767269, 0xCC296977, 0x090DC481, 0x878085C8, 0x5B5EB3A4 },
                .y = { 0xEA981B91, 0x4562FDA0, 0x323A1E1C, 0x29C5FB70, 0x9EBDAC87, 0x497CE7B7, 0x45320DD5, 0xE71B327E }
        },
        // 174G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x4713A3B0, 0x3D368777, 0xEB28249C, 0x07C98652, 0x027898CC, 0x9F80D4D9, 0xE3EE9FDB, 0xEA255DF3 },
                .y = { 0xF97F0C19, 0x75A20DA5, 0xC59DCB31, 0x48F3D80D, 0xE13A4370, 0x68AF22B0, 0x9D4F5BD6, 0xE3162CAF }
        },
        // 175G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xA24B5F7F, 0x029FC41C, 0x0801DB99, 0xE94EC19B, 0xEE43BDAE, 0x56BE9E05, 0x6CAD4049, 0xE7E3AF3F },
                .y = { 0x67AD20AA, 0xBB294C19, 0x95886469, 0x185EC507, 0xB4FBD595, 0x91BB4ADF, 0x820B6D8F, 0xE95F8615 }
        },
        // 176G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD5C74B93, 0x414D3313, 0xDB6D9A91, 0xF14256EC, 0x43F2C9EC, 0x3E4FCAB8, 0x22BA1D4F, 0x14F49598 },
                .y = { 0xAFA4716D, 0xBBF13474, 0x41976280, 0xD23899E0, 0x1C794FA1, 0x8AFC3854, 0xE78B6E92, 0x4C298B97 }
        },
        // 177G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x9F6527EF, 0x7F3B4DAB, 0xE02067F8, 0xB131B783, 0xBD650082, 0xE8D5C495, 0x13886452, 0x6782C952 },
                .y = { 0xBE9CD781, 0x20645C0B, 0x0ED2C23F, 0x50F8B875, 0xE0115E04, 0x3984D4D2, 0x7F4CEB38, 0x3D9083FB }
        },
        // 178G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xEC10452F, 0x45FC0B26, 0xD493C214, 0xB1476271, 0x60B687CA, 0xCA2530DE, 0x92E2698C, 0x60D043EC },
                .y = { 0xC78291BA, 0xEE908113, 0x01127B81, 0xFDD6B528, 0xF177BE6C, 0xF1067634, 0x35634326, 0x8E6402DA }
        },
        // 179G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x816307D2, 0xCDA0B99E, 0x554FC52F, 0x235B7E71, 0x57C17902, 0x986131C7, 0x9E06ABAB, 0x6E6471BE },
                .y = { 0xC3A40C18, 0x54ED8CB5, 0xB03CDB83, 0xF98ADC48, 0x4E95A091, 0x3B3E520D, 0xB11F94BB, 0x04409B44 }
        },
        // 180G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xB8E53E43, 0x19928A29, 0xB36C8EF6, 0x4BE80DB7, 0xCB08AA09, 0x10463B29, 0x91A932C7, 0x1D0B62C7 },
                .y = { 0x39A5FAFA, 0x445CD7F9, 0x2F40BD56, 0xB665A993, 0x0EDF9B74, 0x3AAD99D7, 0x4990D881, 0xE6D7A882 }
        },
        // 181G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xF00DE2E0, 0x451EB127, 0x66668D24, 0x3801438C, 0x68E8EEBF, 0x3AC0566F, 0x80125E3C, 0xDF1CC8EB },
                .y = { 0x3DF7D040, 0x097156C4, 0xA2DE2F0A, 0x820B57B8, 0x13BF412B, 0x9B06D77B, 0x8BA783C7, 0x44063F4F }
        },
        // 182G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x3E98FB58, 0x703FBF85, 0xE8B80AFA, 0xA87B6CCE, 0xF23B6FBA, 0x90A30510, 0x432811F0, 0xC22766F6 },
                .y = { 0x1BDE8EF5, 0x373F28F6, 0x806E6A4A, 0xD17FFD32, 0x30068FA6, 0xA42B89C4, 0x07EDA291, 0x9E6C62BE }
        },
        // 183G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC00A3EC5, 0x1ABCA512, 0xE1CA0151, 0x2D1AE5BC, 0x0F9D10A3, 0x1F228331, 0x460CAED3, 0xAB071EFB },
                .y = { 0x9C20D689, 0x9AA89723, 0x65B9FC54, 0x78B388A6, 0x86227BE6, 0x2BFCBDD7, 0x46BC72B7, 0x93EEE05E }
        },
        // 184G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x77990133, 0x8BD34922, 0x8CC815C9, 0xB373FC33, 0x82353102, 0xA4FE77A1, 0x67929616, 0xBC3255B8 },
                .y = { 0x512D531D, 0xFF7630F8, 0xB9130124, 0xA78B2884, 0x97E79200, 0x13057E80, 0x6BA212E2, 0x7F3B9800 }
        },
        // 185G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xEFFD64DE, 0x9D5ADF6D, 0xF55A405A, 0x49B94110, 0x98C7AF30, 0xB9CF8205, 0x22D4F0A6, 0x60AE7DB9 },
                .y = { 0xC7FDECE0, 0x0D0DCB43, 0xB4D00AE4, 0x92862F92, 0xC1060C6B, 0x63829E08, 0x461872FC, 0x02094381 }
        },
        // 186G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xBB782A44, 0xB65A4BAA, 0x84A74E34, 0x8C3196D4, 0x063508D5, 0x6346FD68, 0x7A131723, 0x8E6E3287 },
                .y = { 0x0D30B69E, 0x0F62574D, 0xC917518C, 0xC5D940F2, 0x38ECDA34, 0x24373628, 0xDA193B39, 0x44DC97D1 }
        },
        // 187G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x35FAB9EE, 0xCBD7ACCF, 0xEACEF129, 0x09529F15, 0xEB1108C0, 0x3EFAB6A0, 0xD4B66F57, 0x1DEBE929 },
                .y = { 0x82228ED7, 0xE22771D9, 0x68F15B7E, 0xB5B95F17, 0x45CAC02F, 0x83EF606F, 0xED6AFB93, 0x8C4B92FB }
        },
        // 188G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x639C2ADC, 0xBDD6F00E, 0xC4919A7B, 0xFEF8D99C, 0xFCA979F0, 0x814AE4AC, 0x718ED00D, 0xD4857935 },
                .y = { 0x4C7C1314, 0x53396412, 0xEBFE39EF, 0x7F770121, 0x50D30BD5, 0xD5E399A3, 0x616C4B8E, 0xA5BF98F1 }
        },
        // 189G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x2AAF72BF, 0x451421F2, 0x7A9B0027, 0x26761E7C, 0xE2093C60, 0xEAE044E1, 0xB0A990E6, 0x5C6E7695 },
                .y = { 0xBA0C0A27, 0xBFD9B953, 0x68FC836A, 0x37F44FBA, 0x6C4D82A6, 0xE0F25AF1, 0xAEAA4ADF, 0x4462AEB6 }
        },
        // 190G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD39E14AB, 0xF63DEAAD, 0x22E1F72B, 0xD42EB79D, 0x2388E45A, 0x72EA9853, 0xCAB94E0D, 0x7F89A0AC },
                .y = { 0xAEE245A8, 0x68590B6C, 0x85C6673E, 0x98A487E1, 0x8175C636, 0xE1B2E842, 0x1AF41E18, 0x393B93CE }
        },
        // 191G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x23BF16C5, 0x1DB25835, 0x40ABFB92, 0xB5A45E02, 0x02196EBD, 0x16BBB23C, 0x23495D10, 0xBCA934A2 },
                .y = { 0x97A7A75C, 0x94A3973B, 0x2D419BCC, 0x143518B3, 0x62ED0EF6, 0xFC0A6B71, 0xE8851937, 0xDF476018 }
        },
        // 192G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x4E6916C6, 0xC0F2AFFC, 0x811842DA, 0x6FB94957, 0x24B4D157, 0x6034BCB6, 0x992EFB90, 0xDE2EFDC7 },
                .y = { 0xAC793C87, 0xD66F7ECE, 0x7DC6FDCD, 0x02F02626, 0x9AA1C501, 0x90D3235C, 0x2B4666F0, 0xF6E49496 }
        },
        // 193G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x662E97DA, 0x13832C69, 0xAA2CD727, 0xCD8CE2B4, 0xCF1A7DC0, 0x74F2EB8C, 0x459A2E53, 0xF4D7FBBF },
                .y = { 0x1381E6A4, 0x22753CBB, 0x547B8688, 0x4FC9CE29, 0x4CD190E4, 0x66C734B2, 0x734A973F, 0x4FB516B9 }
        },
        // 194G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x7334F4F6, 0x9B340777, 0xB7C30F72, 0xCB60B968, 0xA9EF0542, 0x5E08A78F, 0x541CDAC3, 0x04EC9CD5 },
                .y = { 0x9004D469, 0xC0F7BB6F, 0x23343D3D, 0xFD9EE387, 0xF2D33309, 0x429CA212, 0x14F9A600, 0xA00D6DA3 }
        },
        // 195G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x3B07BD14, 0xA513CB98, 0x02F03468, 0x76498EFF, 0x585137D7, 0x2BB7EB63, 0x25CC7B23, 0x0466EA73 },
                .y = { 0xEC7C6299, 0xE01D9523, 0x41571614, 0xBC49F32D, 0x3E74A6FC, 0x060AC38E, 0x001CBAAC, 0x5ED16392 }
        },
        // 196G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xE72446B0, 0xD3F4F96D, 0xFB0A772C, 0xB7B4DE4C, 0x0EF6F0BA, 0x97709605, 0x7447CA22, 0xE02FE7F3 },
                .y = { 0x2D03E9E9, 0xC993A6D9, 0x40B4B0E1, 0xD6708A76, 0xF2F19F15, 0xCD0F158C, 0xA4963332, 0x9F752B4C }
        },
        // 197G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xF9FF5A7A, 0xE5CA2589, 0x785FA633, 0x240B3B3A, 0x660D979A, 0x088DC130, 0x2FD3C9EF, 0x4B48FE9F },
                .y = { 0x0F986225, 0xF0AB66CF, 0x22FA0C9D, 0xAC9B262A, 0x35B878A2, 0x8B6B8BAD, 0x5B895772, 0x4C90E885 }
        },
        // 198G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xB9107999, 0xA330092F, 0xE869BD79, 0xB5C70CBD, 0x70D4ECD7, 0x94D9C879, 0xF66785F3, 0xC86F5766 },
                .y = { 0x4A26B5F5, 0x11C74EA9, 0x37088195, 0x58216846, 0xFBA08D49, 0xF14D11DE, 0xDF4CDA7F, 0x362032BC }
        },
        // 199G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x20432815, 0x250F01C4, 0xB24F29CC, 0x1C3B6728, 0x13FFE5EC, 0x41ABF761, 0xFA9D03B8, 0x84665149 },
                .y = { 0xFB0CBD9F, 0x7C35FA68, 0x338A2FFA, 0xACF49F67, 0xE6F143B3, 0xCCF2D7DA, 0x09DD9C6E, 0x09282B49 }
        },
        // 200G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x40670316, 0x247BA125, 0x6EB6C8D8, 0x8882DEC6, 0x2460F3D0, 0x27E64793, 0xEF48E6D2, 0x0D6228CB },
                .y = { 0x8366B808, 0x2EE59F04, 0x6145F266, 0x78261737, 0xDBBC6F13, 0xBCD1212D, 0x42EB62B1, 0xB08AB304 }
        },
        // 201G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC85AB647, 0x350BE567, 0x87D73937, 0x60E10C86, 0x5F87004B, 0x79D77D79, 0xB3B8B82F, 0xF5CDF52E },
                .y = { 0x064CBBBD, 0x654AD701, 0xF1A840D2, 0x41387D8F, 0x85CA177E, 0xA6C50545, 0xBB4B88B4, 0x75A4DE7B }
        },
        // 202G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x4EFBF1A7, 0x4A31E9F6, 0xF4736405, 0xBB8FEC39, 0x438B8062, 0xEE1D3C5E, 0xC244354D, 0x7B9CFBCC },
                .y = { 0xBD09DDD9, 0x9A56751A, 0x1BD72BCB, 0xA87DC264, 0x95CB96EC, 0xA768A587, 0x4C759476, 0x65F53544 }
        },
        // 203G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x11B747EB, 0x3A562829, 0xD2D249F0, 0xBCB17625, 0x14B47DD9, 0x666ACB6E, 0x61EAEA54, 0xECDF63C4 },
                .y = { 0x0659F519, 0x38AB47F8, 0x26F1A072, 0x9DE92E9C, 0x4DA11B20, 0xD570F661, 0xEF2D5FCD, 0x58E417C8 }
        },
        // 204G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x2370E842, 0x4A98A964, 0x8F5CA2F6, 0xBE8996E4, 0x9D7AE446, 0x24C81FD1, 0x31B44D03, 0x129B5D29 },
                .y = { 0x2A1C7A67, 0x7D0A2320, 0x91602C76, 0x5F3636F0, 0x808CE04D, 0x008A81B6, 0x14885164, 0xE74F1520 }
        },
        // 205G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xEB6F2DBA, 0xA479D917, 0xE40B2B70, 0x5D1289B7, 0x25E5CB18, 0x6A7D6689, 0x1BC7D5FB, 0x3729037F },
                .y = { 0xD8CC97B6, 0x5FD8C5D2, 0x3ACAA787, 0x158B5708, 0x79C08449, 0x3E5693AC, 0x159916A5, 0xD0AE7AED }
        },
        // 206G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x84226BA5, 0x4AD7A921, 0x3DC076DE, 0xC7A5BF44, 0xFE7C9285, 0x1CDAA0D8, 0x052491CA, 0x1A2985E4 },
                .y = { 0x70674605, 0x90A4E8B0, 0x0A098549, 0x6CBE4399, 0x99344899, 0xCC5965E5, 0xF69C12BF, 0xFDB20094 }
        },
        // 207G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xA6DF520E, 0x7DFBB6C0, 0x4DDD1E84, 0xE39533BB, 0xF44653C5, 0xBE25AAC1, 0x209241F9, 0x4B65D579 },
                .y = { 0x8648AD7A, 0xEDB34F5F, 0xABBDA12A, 0x2674B77E, 0x23EAD44D, 0x0989B174, 0xC49A183A, 0xBD0FA4C5 }
        },
        // 208G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xFD52CED4, 0x9B6130A2, 0x5D50773E, 0x9BC0B8B6, 0x9BFCC8DB, 0xDD08F94F, 0xED190168, 0xDD33197C },
                .y = { 0x07F21414, 0x3062B5C7, 0x19839DDB, 0x7244234E, 0x9877267C, 0x630F6AD8, 0xC868A7D3, 0xB283DDCD }
        },
        // 209G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x1AC9656D, 0x716D2C38, 0x658C8D98, 0x3861AC24, 0xE9250D94, 0x705C516E, 0xB1571FAE, 0x948CEDA6 },
                .y = { 0xDB5EE109, 0x4FC7B2B0, 0x281089B5, 0xFBC80EFC, 0x4CD7F66A, 0x2BA6730F, 0x4D71912B, 0x87BCAF9D }
        },
        // 210G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x3A498EB9, 0x63A9BC7D, 0x97D8C7BE, 0xF60F1919, 0xB6DBC431, 0xFECACBC4, 0x3FD00704, 0x396AF8D8 },
                .y = { 0x9464C88C, 0x1C36FB77, 0x5F8680F0, 0x468C66D3, 0x2043D81C, 0xE78C8498, 0x69C7B867, 0x2B37F5D3 }
        },
        // 211G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xA4DA0512, 0xCDD121A7, 0xAA5303F6, 0x4EF507BB, 0x1BBE5F09, 0xB84ECD02, 0x3EDA0ED0, 0xDA80BF3C },
                .y = { 0x77207AEF, 0xE834CF79, 0x3F15BF97, 0xACA63750, 0xC3DE245A, 0x110E4295, 0x6DD117E0, 0xF7CC3BD5 }
        },
        // 212G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x34CCC663, 0xA7AF8E47, 0x682F7D41, 0x20C9A897, 0x37EF19F1, 0x3870B0F8, 0xE519FFB1, 0xEDED7BC1 },
                .y = { 0x7A21CB77, 0x905C8679, 0xDC04D028, 0x9084CBAB, 0x5AD98998, 0xAE60D0CF, 0x1B9596A7, 0x35BA23C8 }
        },
        // 213G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x9EBEC0D7, 0x687CC90C, 0x1E29C51B, 0xA094AF09, 0x0F5FAE25, 0xB288D350, 0x404A9373, 0x85EF1CE3 },
                .y = { 0x5E671536, 0xA4B6EE05, 0x066FCBFC, 0x7886A321, 0x9541E5E1, 0x6CE84B2F, 0x85419D49, 0xDB6ECCAF }
        },
        // 214G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x7ACD508D, 0x57BD7733, 0xB91548BE, 0x9C024F50, 0xECE4D991, 0x6074DC7C, 0xCD2D11F9, 0x7AB0D5AE },
                .y = { 0x91209734, 0x38544525, 0x8DCC74CD, 0x01C3371F, 0x0D0F927B, 0xE5FB9108, 0xD5D3DA01, 0x1BA64389 }
        },
        // 215G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x6A7928E3, 0x928B83F5, 0x98BE85A6, 0x9A98AD74, 0x08B33F84, 0x6AB45D60, 0x69C75813, 0x4BDFC8C2 },
                .y = { 0xFE42B52B, 0xC25DDA94, 0xAB58CF4E, 0x52D96987, 0x261F4A14, 0x90CD76F5, 0x34A8E2D6, 0x3958E9F7 }
        },
        // 216G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x29EC25A5, 0xA0DF5ABD, 0x77FD4DA3, 0x3D6AFE1C, 0x819EE1F1, 0xFEB9380A, 0x4CA4D7D3, 0xA4756513 },
                .y = { 0x7957613B, 0xA52F7FA8, 0x282E7C91, 0x0E94D629, 0xB18809F1, 0x3B6E9532, 0x2AA7DE65, 0x2CEA6745 }
        },
        // 217G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x5F28C781, 0xF87BC5AD, 0xC6FA266A, 0xF1D84A3A, 0x9E8B432D, 0x16A11DA1, 0x6746EB37, 0x4882444F },
                .y = { 0x3C7010FB, 0x5BF07C38, 0xB5A9F97F, 0xB55D9DBA, 0x47CD166B, 0x1C0CE375, 0x76678B23, 0xE0796E95 }
        },
        // 218G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x55FAB314, 0x0A043E11, 0xB824D9F3, 0x9F121C10, 0xEC2DB24C, 0x4BEFE512, 0x55F729C4, 0xBD3D6533 },
                .y = { 0xF2324331, 0x6738DB7D, 0x0CBEFC37, 0x07A955CE, 0xF8005551, 0xDF5C57FA, 0x24706FF7, 0xBC5F9202 }
        },
        // 219G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x625FCDCF, 0xBC572366, 0xD0125229, 0x99854DCC, 0x9A845606, 0x636FED13, 0x1A32AB23, 0x31DCC27C },
                .y = { 0xD0C74D67, 0xC1BB6B28, 0xB7F2DB89, 0x8CF9F549, 0xC5973373, 0x53FA58B2, 0x2E55F478, 0xCB4C852A }
        },
        // 220G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD8836938, 0x2A9ED7BC, 0x0B99311E, 0x086043F3, 0xDA30E587, 0xE05CD307, 0x9FC2A9F3, 0xB97C3B7E },
                .y = { 0x00674769, 0xFBE028CA, 0x6431C73D, 0xBA85AB37, 0x6739B406, 0xAC45401F, 0x7FA80BCE, 0x0628114B }
        },
        // 221G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x5E0833B4, 0xF9F5D623, 0x3EEC934F, 0xC645535A, 0x91905168, 0x17DFEF48, 0x09157684, 0x73DF2766 },
                .y = { 0x9E58CC1F, 0x17A22C37, 0x5508F08D, 0x52B52CDD, 0x8A37B4F5, 0xE1C4006A, 0x81E5C936, 0x693D2FB9 }
        },
        // 222G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x536EF09D, 0x68EEB05C, 0x9A275A9C, 0x173CF200, 0x61E02EC7, 0xE7187009, 0x91BE32D4, 0x940135C3 },
                .y = { 0x95664FE9, 0x860CE336, 0xDD54CF61, 0x29C3183D, 0x79040585, 0xA79F0765, 0x7B3F4E6F, 0xB545572B }
        },
        // 223G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x78A414B2, 0x70AD14E4, 0x0CBAA1D8, 0x52B72E92, 0xB6BB6FDB, 0x10EDD1EA, 0xFD78C821, 0x12ACBA6F },
                .y = { 0x1458FA14, 0x8FDB75E8, 0x9DEE8C5E, 0xC423D420, 0x94B6104A, 0x9A8463F5, 0xCCEE9BE8, 0x2FDE2BE6 }
        },
        // 224G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x9C0859C3, 0x082736D1, 0xB269386A, 0x89EA5516, 0x1AA87B33, 0xF2507187, 0x704E8236, 0xE9D82F5F },
                .y = { 0x42E855F5, 0x78346124, 0x395E00D8, 0x209F50FE, 0xE6E7E62B, 0xCD9E03AA, 0x5E5BE37B, 0xB4B4959E }
        },
        // 225G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xA208937E, 0xD342772B, 0x70A558CC, 0x314AB8B2, 0x615717A3, 0xB2B0ECEE, 0x3DD54A93, 0x8D0B9DB0 },
                .y = { 0x71A6DB88, 0x15209B17, 0x58A1AFE7, 0x33C8931C, 0xEC4EC6D8, 0x79E3B6E4, 0xEF1F485D, 0x67EFBE60 }
        },
        // 226G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x971F3773, 0x4D263443, 0x4D973639, 0xE70E6F8A, 0x1DC86C56, 0xDB8D8DE1, 0x7A8CBA58, 0x194F9E9D },
                .y = { 0x66388D73, 0x78A2E8E1, 0xB8651216, 0x054CA393, 0xC530BD5A, 0x9C5F486C, 0x13904B84, 0x0E54D13E }
        },
        // 227G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x0749F50F, 0x28F1C585, 0x1E5B1F5B, 0x132386A4, 0xBA5FF74A, 0xAB78AEC2, 0xE7586D35, 0x711754A9 },
                .y = { 0xC92D5178, 0xC2385603, 0xF346333D, 0x5BF37C09, 0x2D8DA734, 0x4207C33A, 0xF4C09CE8, 0xF1A7AB09 }
        },
        // 228G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x27A27759, 0xF172E50E, 0x79166B11, 0x0466858B, 0x48311F07, 0xE486273B, 0x88AC9629, 0x3CE42AE1 },
                .y = { 0x96B19775, 0x2306C812, 0x918A6C62, 0xD137DDBF, 0xA3BFD511, 0xE13A7015, 0xEC454A39, 0xA879BE93 }
        },
        // 229G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x9C7C0B4A, 0xC481BB9A, 0xB30F0A99, 0x026D81BE, 0x7A1B381B, 0x41392AD8, 0xB15579F6, 0xD44754A5 },
                .y = { 0x7D8F660A, 0xB02E6837, 0xDBC8D5B4, 0x6ADD4477, 0x4D66BCEC, 0x3B4EFE82, 0x09D0DCA3, 0x78964C01 }
        },
        // 230G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xE270A325, 0x4494D526, 0xBF1FE4FB, 0x08A3D0DC, 0x850117F6, 0xADA2423B, 0xCA8D6CD8, 0x213056F6 },
                .y = { 0x31EC0AB1, 0xFCAF0B78, 0x68B8E1BE, 0xE94CDC14, 0x2FEE3A84, 0xAA48DCAF, 0x5E381227, 0xA5286EFE }
        },
        // 231G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD85221E5, 0xD14A7D4E, 0xBC99037B, 0xE4C19C52, 0x1E9AC3F7, 0x2FC47AA1, 0xC750EB1C, 0x72FFFF6C },
                .y = { 0xB5ACF60E, 0x85E5C154, 0x74CE0518, 0x70A430A6, 0xE5BE466A, 0x7675DC40, 0xC4DD37C5, 0x04C20577 }
        },
        // 232G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x500491E6, 0xAD77F062, 0xEC0FB1EE, 0xFC24B431, 0xAE7B23BD, 0x9D85430C, 0x52BD0200, 0x094FCC94 },
                .y = { 0x27730025, 0xE7CBB1E8, 0x80144561, 0x52DCA275, 0xCC164683, 0xFB17EF2B, 0x5091CDD8, 0x24B0A95F }
        },
        // 233G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x9E301AD0, 0x1CF4BC88, 0x57CB0179, 0xA7944FB9, 0x7EC4DA1C, 0xCC61F960, 0xCF7320CD, 0x50285056 },
                .y = { 0xD2915739, 0x5F28F104, 0x9924620B, 0xC5455E15, 0xC220710F, 0x8AF71A68, 0x6BEEEF82, 0xCC37F43F }
        },
        // 234G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xB607426F, 0x07DB3583, 0xFEACD8DF, 0x126BE356, 0x73D39F83, 0x9CC48312, 0x5D638449, 0x201E9C71 },
                .y = { 0x4D5DEF15, 0x7F3AB6E4, 0x21F4191E, 0x68F5BC2D, 0xC8AB2213, 0xAD42A3AD, 0x74CFAB42, 0x33827717 }
        },
        // 235G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x951C9DAE, 0x2C19D407, 0x60B1F6A6, 0x26F66775, 0x55E0A043, 0xE28FF627, 0x6D0A0E81, 0x62A5DD6C },
                .y = { 0xA33F4118, 0xA7410810, 0xC0EEA589, 0xA66DADF9, 0x94D9DFF5, 0x099ACD69, 0x4B773ED6, 0xB163484C }
        },
        // 236G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD5F14EF1, 0x0D0D00A8, 0xBFE11E01, 0xD3323A58, 0x21672FCC, 0x3B3ED4D4, 0x4F09069A, 0x0A30AE00 },
                .y = { 0xF484ECAC, 0x2E0B384E, 0xD2B39D4D, 0x187FF7CC, 0xB8F4F60D, 0xAA3F6715, 0xCD3F7856, 0xDAC73188 }
        },
        // 237G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x6A14ABF2, 0xB3626B37, 0x4800400D, 0xDAD48694, 0x420C372C, 0xDF0F9EAA, 0x87C49165, 0x66E06BC3 },
                .y = { 0xD43ACE09, 0xA8EC8D58, 0xBD88BDC6, 0xC70AFA05, 0x30406B65, 0x02C3EA75, 0x567AF8C0, 0x34D831E2 }
        },
        // 238G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC676351E, 0xBB74A206, 0x88E6DD11, 0xAB277104, 0x7C945318, 0xFB2AAD50, 0x32BB9757, 0xEF1F2CE4 },
                .y = { 0x03C8087B, 0xAE769BE6, 0xFAD30EDD, 0x00117AF0, 0x8B2D37DA, 0xE4A6CA10, 0x854979BA, 0xBAE1579F }
        },
        // 239G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD2EA70B4, 0xDDFFB87C, 0x6BFB1C75, 0xA8A30827, 0x07D345F7, 0x3FC8F845, 0x07C99374, 0xA3C82201 },
                .y = { 0x8E52C633, 0xE3861A47, 0x2F93120D, 0xA3FA7335, 0x3165ED5C, 0xB86B05B9, 0xB306733D, 0xC03F5880 }
        },
        // 240G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD295A458, 0x85CC1158, 0xA81821F7, 0x52625915, 0xDABF3D08, 0xEAE65A00, 0x2D2DB6D9, 0x8567E049 },
                .y = { 0x3565303B, 0xF6C9D65B, 0xA7CB419F, 0x3928349B, 0x1275714C, 0x4AA7CD7A, 0xEC0FDCDA, 0x921EF60B }
        },
        // 241G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x984E3FDC, 0x57AB12A3, 0xA6F45AA0, 0x239AC554, 0xB33FACE5, 0x602AD857, 0x3A403957, 0x8B5281C2 },
                .y = { 0x08EAE36A, 0x94E5C076, 0x0DC9BC05, 0x6DA18F73, 0x5AD7D1CB, 0x0623FBB1, 0x883D0A20, 0x4EEEC087 }
        },
        // 242G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xE7BC8667, 0x1F27A611, 0x9458D3E4, 0x2489AEB4, 0x12D1D599, 0x0E21C27F, 0x86208F32, 0x0395C94A },
                .y = { 0x1D9D25F7, 0xBF1BD26A, 0xDE284B48, 0x168E66D7, 0xD1544F97, 0x6A4216FE, 0x748E4B3B, 0x74F30713 }
        },
        // 243G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xE5EB7376, 0x89563B16, 0x902E6580, 0x66E222F7, 0xAAD80C7F, 0x81B721C8, 0x75DD4FA6, 0xCBF9A334 },
                .y = { 0x48415259, 0x868C6A64, 0x3CB46440, 0x3D98F8AE, 0x1CDF5428, 0xD1FEA41D, 0x61BAF8CA, 0xAF046608 }
        },
        // 244G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x83C1FAD5, 0x0622879A, 0x12FBBB42, 0xE0390519, 0xC27C3BF2, 0xF18C5AE5, 0x4C24AB07, 0xD037C06E },
                .y = { 0xA68B535A, 0x915C9290, 0x57EDA658, 0xE9D952E6, 0x87AE0511, 0xC8D56272, 0xFD1AA47C, 0xC51175B0 }
        },
        // 245G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xBFAAA237, 0x8B1CA80A, 0xC75F7CDF, 0xA50CF163, 0x91B00B68, 0xE6B2ACC7, 0x634880B1, 0x7228E388 },
                .y = { 0x445C587E, 0x587AB652, 0xD2F8E1B1, 0x6DD44E83, 0xEDDC8968, 0x713B2F6E, 0x8A0A053B, 0xF726F052 }
        },
        // 246G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xF5309B27, 0x7B94DF7B, 0x048AE38F, 0xBFD4B86E, 0x1B82F5BC, 0x25399CBC, 0xFA78A208, 0x0FCF8F88 },
                .y = { 0xCA16B171, 0x405E8F18, 0x58BE96BB, 0x7C570C52, 0xA12C0010, 0xA9F56CA5, 0x7336F7C5, 0x7D8E2A1A }
        },
        // 247G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD7AC2B21, 0xB6EEC90D, 0x8C6D3B2C, 0x247CBA7A, 0x1D8E3318, 0x61ED6B9D, 0x7F736944, 0x902A5E7D },
                .y = { 0xD4192BF2, 0x1D880838, 0x984AD887, 0x23420A8A, 0xDC485297, 0x5C1890F6, 0x8D708602, 0x901EC12C }
        },
        // 248G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xB3E0835A, 0xE1B3B137, 0xD1B856B5, 0x554F462F, 0x6FB893CC, 0x33E57504, 0x3722667A, 0x016FC35F },
                .y = { 0xF8741724, 0xC61BBAC1, 0xEE8F132C, 0x9CE209AE, 0xED448442, 0xEDE009E2, 0x3DAFFB5C, 0xC186D922 }
        },
        // 249G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x9AAFA426, 0x73574DAA, 0x58A4AA0A, 0x9947DE6D, 0x343F4F94, 0x917355BF, 0xA0794F94, 0x40FF8852 },
                .y = { 0xF6B226DC, 0x04A7835E, 0x1BB763FE, 0x93B55BBD, 0xE08B0053, 0xA3578393, 0x82EF44FD, 0x7181A69F }
        },
        // 250G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x19D45325, 0x9F7C68BF, 0x9643D151, 0xF2BB9530, 0xC7D91075, 0xD88C04AF, 0x2B97D542, 0x71ABD7E1 },
                .y = { 0xE77C22F1, 0x697CA7CB, 0x03FD9CE6, 0x170802A0, 0x43FB54AC, 0x801FB173, 0xA94E416F, 0xED5B60FE }
        },
        // 251G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xD5A12003, 0x53C55500, 0xC157FC81, 0x159930C6, 0xC90926C8, 0x89A73FB5, 0x8B54E950, 0x9D7F4238 },
                .y = { 0x6D95D509, 0x37C3E761, 0x71D5A1A1, 0x323DA0A8, 0x2B9CCE10, 0xB4DDBC78, 0x6F4B006A, 0x2B585AED }
        },
        // 252G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x2EA9459D, 0x3C276418, 0xB05E63C9, 0x9F5D44DF, 0x3B6A8689, 0x682DD597, 0xD4DF7389, 0x23AF67AE },
                .y = { 0xE2CA1387, 0xB42DED60, 0xB5970584, 0xA2113346, 0xC809A897, 0x1F99B0C7, 0x60301B7D, 0x164D0D0E }
        },
        // 253G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0x73EE3A46, 0x97DC7599, 0x8CB5A5BE, 0x37772BD5, 0x83A17E4A, 0x85A3F3A4, 0x5324B823, 0xFB494141 },
                .y = { 0x2CF3D3D9, 0x672A6554, 0x28CA9CA5, 0x7D10AABC, 0x23C80C39, 0xF7B308E9, 0xCB32E3FD, 0x62667900 }
        },
        // 254G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xB67310D3, 0x29DB9607, 0xB7180215, 0xF8598A3E, 0x76AA99EA, 0xD0EFAEDD, 0xAD0FDB0D, 0xC1549563 },
                .y = { 0xBC39E126, 0xAD350DF8, 0xDA6B2D48, 0x4559CB14, 0xC8316F2F, 0xE34526FD, 0x9EF2A951, 0x846E4696 }
        },
        // 255G
        {
                .generator_index = 0, .infinity = 0,
                .x = { 0xC06526E3, 0xE111F348, 0x48C557C1, 0x03A1B36D, 0x97E0FA40, 0x75100EF6, 0x0A0DA5F9, 0x5AAB7F88 },
                .y = { 0x1DEA81EB, 0x08F5BAB0, 0x52309BEF, 0x8D834FB0, 0x134422D5, 0xC0ACDFC5, 0x17DF49AE, 0xB7B5E685 }
        }
        #endif
};

