package paseto

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const testPrivateKey = "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0d0a4d4949456f77494241414b43415145417878636e47724e4f6136426c4152345870705064746146576946386f7279746c4b534d6a66446831314c687956627a430d0a35416967556b706a457274394d7649482f46384d444a72324f39486b36594b454b574b6f72333566364b6853303679357a714f722b7a4e34312b39626a5236560d0a33322b527345776d5a737a3038375258764e41334e687242633264593647736e57336c5a34356f5341564a755639553667335a334a574138355972362b6350770d0a6134793755632f56726f6d7a674679627355656e33476f724254626a783142384f514a4473652f4b6b6855433655693358384264514f473974523455454775740d0a2f6c39703970732b3661474d4c57694357495a54615456784d4f75653133596b777038743148467635747a6872493055635948687638464a6b315a64353867590d0a464158634e797975737834346e6a6152594b595948646e6b4f6a486e33416b534c4d306b6c77494441514142416f49424143574c6154567730503463376b394b0d0a7048306d623234634d6478667a6156544571327955625051566641367046306b7a7341414848504955577972374d315a74555854697373707766752f396d4a4f0d0a32617551546d3168384b5a49622b34354b595564656f5a52793530314a316579682b4c754146523131397756464c434d747573466652503338626c59715079540d0a6b4957416d67494241526f38754642614273485a366c676a45506a63616b4773714e2f686f4550756168444a48577133784f684a4f644e6e2f5261424f7370760d0a634970796f727636677835724947507135647379635973696b2b4d464130676c397768625344623444436e5646507372556e742f2b347245704c33686c7150460d0a4b65494535775243696579594b4f3631747835655a6538474f57415030424a6c4245764f534d626c6b4d74714c5646624e387a59523345717865564a4e43476c0d0a714b334a483345436759454139734676767a76757a525645367547494b316757346d634d37513477654e567a613156582b63536f53676242512b64466c4f62340d0a4d7955334437315979304f51384e4f6f3976626b43362f31776d36476341302b7944645973767830646c6f70474d59667064624c4d624c35696f43635530684a0d0a4764783736704b735636444d5a3046786668523346547544556936624c5639447342592f796e36304679585635636337645570344b553843675945417a6f79530d0a73633536385455733230673654635464473134783067334d7069376a45736f666a696a34694e516c3874585a494b386658694a67785952484d354e627173344b0d0a6754566765466c6f566a6d716d4f44316d52685336513153653541354754735564385674375a445150476f7155633654526a53322f374f4e4d3057346c6b356f0d0a4d614134737a4b6735566f334636384b4f4a6a735a6235727571536d4451416456546e30626a6b436759427657347961754f6c6b4642307541756e34356141750d0a50474e51392f3559436277307a4363507950684a73424b34476a38456d3965572f557945426564306b2b4674545a674c4842422b56634b4c4a47583357344c680d0a794668334c6764424168395a31732b68662f586a542b6e64333379732b517045615952697342366d7a534a783173377048304d2b696355523659614f533165340d0a74394843434c77745668335a764c66516a764c3763514b4267514362704e4253446c3855626c616238795345502b6e423273772b466b6e316e485665546c4e540d0a41387174435069447365504a506b3272324d6f46625056656878645863615832306173645a586f374a333948627057447852474e4c6f334f4d4e4c6d4557414f0d0a4651634f4d7362494439524f437856746e5147645538622b4d506130784f61394a70677a614e35586c6844583176346a776843355a7247315671634f4f747a660d0a77536c512b514b426747327a6c56353030444b6d4f697042662f5671307a4255434c3546526a4f6c4963785078474168426a6c4a6b58526d71506236723143550d0a355a447031756773554f7548466d5171524c486b6b5878376a6a384e355368757176354d504367693757746a7568737a6b306f68524c672f73314c58484638650d0a4b5a6c365246446f736473363041564c5458462b7671414c4c464b495751322f6a4b426a4b374334656d326863735331705157620d0a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d"
const testPublicKey = "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0d0a4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b43415145417878636e47724e4f6136426c41523458707050640d0a746146576946386f7279746c4b534d6a66446831314c687956627a4335416967556b706a457274394d7649482f46384d444a72324f39486b36594b454b574b6f0d0a72333566364b6853303679357a714f722b7a4e34312b39626a52365633322b527345776d5a737a3038375258764e41334e687242633264593647736e57336c5a0d0a34356f5341564a755639553667335a334a574138355972362b6350776134793755632f56726f6d7a674679627355656e33476f724254626a783142384f514a440d0a73652f4b6b6855433655693358384264514f473974523455454775742f6c39703970732b3661474d4c57694357495a54615456784d4f75653133596b777038740d0a3148467635747a6872493055635948687638464a6b315a6435386759464158634e797975737834346e6a6152594b595948646e6b4f6a486e33416b534c4d306b0d0a6c774944415141420d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d"

var rsaPrivateKey *rsa.PrivateKey
var rsaPublicKey *rsa.PublicKey

type TestPerson struct {
	Name string
	Age  int
}

func init() {
	privateKey, err := hex.DecodeString(testPrivateKey)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(privateKey)
	if block == nil {
		panic("ssh: no key found")
	}

	rsaPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	publicKey, err := hex.DecodeString(testPublicKey)
	if err != nil {
		panic(err)
	}
	block, _ = pem.Decode(publicKey)
	if block == nil {
		panic("ssh: no key found")
	}
	rsaPubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	var ok bool
	rsaPublicKey, ok = rsaPubInterface.(*rsa.PublicKey)
	if !ok {
		panic("incorrect public key")
	}
}

func TestPasetoV1_Encrypt_Compatibility(t *testing.T) {
	nullKey := bytes.Repeat([]byte{0}, 32)
	fullKey := bytes.Repeat([]byte{0xff}, 32)
	symmetricKey, _ := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	nonce := bytes.Repeat([]byte{0}, 32)
	nonce2, _ := hex.DecodeString("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2")
	footer := []byte("Cuon Alpinus")
	payload := []byte("Love is stronger than hate or fear")
	v1 := NewV1()

	cases := map[string]struct {
		key     []byte
		token   string
		nonce   []byte
		payload []byte
		footer  []byte
	}{
		"Empty message, empty footer, empty nonce, null key": {
			key:   nullKey,
			token: "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTXyNMehtdOLJS_vq4YzYdaZ6vwItmpjx-Lt3AtVanBmiMyzFyqJMHCaWVMpEMUyxUg",
			nonce: nonce,
		},
		"Empty message, empty footer, empty nonce, full key": {
			key:   fullKey,
			token: "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTWgetvu2STfe7gxkDpAOk_IXGmBeea4tGW6HsoH12oKElAWap57-PQMopNurtEoEdk",
			nonce: nonce,
		},
		"Empty message, empty footer, empty nonce, symmetric key": {
			key:   symmetricKey,
			token: "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTV8OmiMvoZgzer20TE8kb3R0QN9Ay-ICSkDD1-UDznTCdBiHX1fbb53wdB5ng9nCDY",
			nonce: nonce,
		},

		"Empty message, non-empty footer, empty nonce, null key": {
			key:    nullKey,
			token:  "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVhyXOB4vmrFm9GvbJdMZGArV5_10Kxwlv4qSb-MjRGgFzPg00-T2TCFdmc9BMvJAA.Q3VvbiBBbHBpbnVz",
			footer: footer,
			nonce:  nonce,
		},
		"Empty message, non-empty footer, empty nonce, full key": {
			key:    fullKey,
			token:  "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVna3s7WqUwfQaVM8ddnvjPkrWkYRquX58-_RgRQTnHn7hwGJwKT3H23ZDlioSiJeo.Q3VvbiBBbHBpbnVz",
			footer: footer,
			nonce:  nonce,
		},
		"Empty message, non-empty footer, empty nonce, symmetric key": {
			key:    symmetricKey,
			token:  "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTW9MRfGNyfC8vRpl8xsgnsWt-zHinI9bxLIVF0c6INWOv0_KYIYEaZjrtumY8cyo7M.Q3VvbiBBbHBpbnVz",
			footer: footer,
			nonce:  nonce,
		},

		"Non-empty message, empty footer, empty nonce, null key": {
			key:     nullKey,
			token:   "v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA45LtwQCqG8LYmNfBHIX-4Uxfm8KzaYAUUHqkxxv17MFxsEvk-Ex67g9P-z7EBFW09xxSt21Xm1ELB6pxErl4RE1gGtgvAm9tl3rW2-oy6qHlYx2",
			payload: payload,
			nonce:   nonce,
		},
		"Non-empty message, empty footer, empty nonce, full key": {
			key:     fullKey,
			token:   "v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA47lQ79wMmeM7sC4c0-BnsXzIteEQQBQpu_FyMznRnzYg4gN-6Kt50rXUxgPPfwDpOr3lUb5U16RzIGrMNemKy0gRhfKvAh1b8N57NKk93pZLpEz",
			payload: payload,
			nonce:   nonce,
		},
		"Non-empty message, empty footer, empty nonce, symmetric key": {
			key:     symmetricKey,
			token:   "v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA47hvAicYf1zfZrxPrLeBFdbEKO3JRQdn3gjqVEkR1aXXttscmmZ6t48tfuuudETldFD_xbqID74_TIDO1JxDy7OFgYI_PehxzcapQ8t040Fgj9k",
			payload: payload,
			nonce:   nonce,
		},

		"Non-empty message, non-empty footer, non-empty nonce, null key": {
			key:     nullKey,
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYbivwqsESBnr82_ZoMFFGzolJ6kpkOihkulB4K_JhfMHoFw4E9yCR6ltWX3e9MTNSud8mpBzZiwNXNbgXBLxF_Igb5Ixo_feIonmCucOXDlLVUT.Q3VvbiBBbHBpbnVz",
			payload: payload,
			footer:  footer,
			nonce:   nonce2,
		},
		"Non-empty message, non-empty footer, non-empty nonce, full key": {
			key:     fullKey,
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYZ8rQTA12SNb9cY8jVtVyikY2jj_tEBzY5O7GJsxb5MdQ6cMSnDz2uJGV20vhzVDgvkjdEcN9D44VaHid26qy1_1YlHjU6pmyTmJt8WT21LqzDl.Q3VvbiBBbHBpbnVz",
			payload: payload,
			footer:  footer,
			nonce:   nonce2,
		},
		"Non-empty message, non-empty footer, non-empty nonce, symmetric key": {
			key:     symmetricKey,
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVz",
			payload: payload,
			footer:  footer,
			nonce:   nonce2,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			v1.nonce = test.nonce
			if token, err := v1.Encrypt(test.key, test.payload, test.footer); assert.NoError(t, err) {
				assert.Equal(t, test.token, token)
			}
		})
	}
}

func TestPasetoV1_Decrypt_Compatibility(t *testing.T) {
	nullKey := bytes.Repeat([]byte{0}, 32)
	fullKey := bytes.Repeat([]byte{0xff}, 32)
	symmetricKey, _ := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	fullFooter := []byte("Cuon Alpinus")
	fullPayload := []byte("Love is stronger than hate or fear")
	v1 := NewV1()

	cases := map[string]struct {
		token   string
		key     []byte
		payload []byte
		footer  []byte
	}{
		"Empty message, empty footer, empty nonce, null key": {
			token: "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTXyNMehtdOLJS_vq4YzYdaZ6vwItmpjx-Lt3AtVanBmiMyzFyqJMHCaWVMpEMUyxUg",
			key:   nullKey,
		},
		"Empty message, empty footer, empty nonce, full key": {
			token: "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTWgetvu2STfe7gxkDpAOk_IXGmBeea4tGW6HsoH12oKElAWap57-PQMopNurtEoEdk",
			key:   fullKey,
		},
		"Empty message, empty footer, empty nonce, symmetric key": {
			token: "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTV8OmiMvoZgzer20TE8kb3R0QN9Ay-ICSkDD1-UDznTCdBiHX1fbb53wdB5ng9nCDY",
			key:   symmetricKey,
		},

		"Empty message, non-empty footer, empty nonce, null key": {
			token:  "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVhyXOB4vmrFm9GvbJdMZGArV5_10Kxwlv4qSb-MjRGgFzPg00-T2TCFdmc9BMvJAA.Q3VvbiBBbHBpbnVz",
			key:    nullKey,
			footer: fullFooter,
		},
		"Empty message, non-empty footer, empty nonce, full key": {
			token:  "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVna3s7WqUwfQaVM8ddnvjPkrWkYRquX58-_RgRQTnHn7hwGJwKT3H23ZDlioSiJeo.Q3VvbiBBbHBpbnVz",
			key:    fullKey,
			footer: fullFooter,
		},
		"Empty message, non-empty footer, empty nonce, symmetric key": {
			token:  "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTW9MRfGNyfC8vRpl8xsgnsWt-zHinI9bxLIVF0c6INWOv0_KYIYEaZjrtumY8cyo7M.Q3VvbiBBbHBpbnVz",
			key:    symmetricKey,
			footer: fullFooter,
		},

		"Non-empty message, empty footer, empty nonce, null key": {
			token:   "v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA45LtwQCqG8LYmNfBHIX-4Uxfm8KzaYAUUHqkxxv17MFxsEvk-Ex67g9P-z7EBFW09xxSt21Xm1ELB6pxErl4RE1gGtgvAm9tl3rW2-oy6qHlYx2",
			key:     nullKey,
			payload: fullPayload,
		},
		"Non-empty message, empty footer, empty nonce, full key": {
			token:   "v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA47lQ79wMmeM7sC4c0-BnsXzIteEQQBQpu_FyMznRnzYg4gN-6Kt50rXUxgPPfwDpOr3lUb5U16RzIGrMNemKy0gRhfKvAh1b8N57NKk93pZLpEz",
			key:     fullKey,
			payload: fullPayload,
		},
		"Non-empty message, empty footer, empty nonce, symmetric key": {
			token:   "v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA47hvAicYf1zfZrxPrLeBFdbEKO3JRQdn3gjqVEkR1aXXttscmmZ6t48tfuuudETldFD_xbqID74_TIDO1JxDy7OFgYI_PehxzcapQ8t040Fgj9k",
			key:     symmetricKey,
			payload: fullPayload,
		},

		"Non-empty message, non-empty footer, non-empty nonce, null key": {
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYbivwqsESBnr82_ZoMFFGzolJ6kpkOihkulB4K_JhfMHoFw4E9yCR6ltWX3e9MTNSud8mpBzZiwNXNbgXBLxF_Igb5Ixo_feIonmCucOXDlLVUT.Q3VvbiBBbHBpbnVz",
			key:     nullKey,
			payload: fullPayload,
			footer:  fullFooter,
		},
		"Non-empty message, non-empty footer, non-empty nonce, full key": {
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYZ8rQTA12SNb9cY8jVtVyikY2jj_tEBzY5O7GJsxb5MdQ6cMSnDz2uJGV20vhzVDgvkjdEcN9D44VaHid26qy1_1YlHjU6pmyTmJt8WT21LqzDl.Q3VvbiBBbHBpbnVz",
			key:     fullKey,
			payload: fullPayload,
			footer:  fullFooter,
		},
		"Non-empty message, non-empty footer, non-empty nonce, symmetric key": {
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVz",
			key:     symmetricKey,
			payload: fullPayload,
			footer:  fullFooter,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			var payload []byte
			var footer []byte
			if assert.NoError(t, v1.Decrypt(test.token, test.key, &payload, &footer)) {
				assert.Equal(t, test.payload, payload, "Payload does not match")
				assert.Equal(t, test.footer, footer, "Footer does not match")
			}
		})
	}
}

func TestPasetoV1_EncryptDecrypt(t *testing.T) {
	testEncryptDecrypt(t, NewV1())
}

func TestPasetoV1_Decrypt_Error(t *testing.T) {
	symmetricKey, _ := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	v1 := NewV1()

	cases := map[string]struct {
		token   string
		payload interface{}
		footer  interface{}
		error   error
	}{
		"Payload unmarshal error": {
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVz",
			payload: struct{}{},
			footer:  baPtr([]byte{}),
			error:   ErrDataUnmarshal,
		},
		"Footer unmarshal error": {
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVz",
			payload: baPtr([]byte{}),
			footer:  struct{}{},
			error:   ErrDataUnmarshal,
		},
		"Invalid token header": {
			token:   "v1.test.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwy.Q3VvbiBBbHBpbnVz",
			payload: baPtr([]byte{}),
			footer:  baPtr([]byte{}),
			error:   ErrIncorrectTokenHeader,
		},
		"Too many parts": {
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTn.Q3VvbiBBbHBpbnVz",
			payload: baPtr([]byte{}),
			footer:  baPtr([]byte{}),
			error:   ErrIncorrectTokenFormat,
		},
		"Incorrect nonce size": {
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTn.Q3VvbiBBbHBpbnVz",
			payload: baPtr([]byte{}),
			footer:  baPtr([]byte{}),
			error:   ErrIncorrectTokenFormat,
		},
		"Invalid token auth": {
			token:   "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwy.Q3VvbiBBbHBpbnVz",
			payload: baPtr([]byte{}),
			footer:  baPtr([]byte{}),
			error:   ErrInvalidTokenAuth,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := v1.Decrypt(test.token, symmetricKey, test.payload, test.footer)
			assert.Equal(t, test.error, errors.Cause(err))
		})
	}
}

func TestPasetoV1_SignVerify(t *testing.T) {
	testSign(t, NewV1(), rsaPrivateKey, rsaPublicKey)
}

func TestPasetoV1_Sign_Error(t *testing.T) {
	v1 := NewV1()

	cases := map[string]struct {
		key     crypto.PrivateKey
		payload interface{}
		footer  interface{}
		err     error
	}{
		"Invalid key": {
			key: "incorrect",
			err: ErrIncorrectPrivateKeyType,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v1.Sign(test.key, test.payload, test.footer)
			assert.EqualError(t, err, test.err.Error())
		})
	}
}

func TestPasetoV1_Verify_Error(t *testing.T) {
	v1 := NewV1()
	const token = "v1.public.eyJOYW1lIjoiSm9obiIsIkFnZSI6MzB9vGJwH3bQzs04XkPPlq2jA3B-_xKzA_qW193-eer9mbZJmgq5zDUY8OV2fVUSZLRVPz4yMe2hFg17riaI8nxSqc1dMnXpwbk2SnUfxyfZ2ZQjKj-g0JiYUrekqvi21YbFGMg6DHWXFlHkX32JY-fEcyu88pwB-VOdJdKX2LVGxVQVVOFBpD7gNXGoFsrYsSAUjMsI80x75NSAuAcTdy3BldR2YA9J0UhOcs-kfQLTOM5unhQvPd9411AaIVfhPtTy0uPooJfsClEjnJnL8Q-uCINjbWnlFtcb2nlYKjbAIXbiM97FvQvakkt6diU0yNV6Fh_C6QCTKZibZzlMLy97QA.eyJOYW1lIjoiQW50b255IiwiQWdlIjo2MH0"

	cases := map[string]struct {
		token   string
		payload interface{}
		footer  interface{}
		error   error
	}{
		"Payload unmarshal error": {
			token:   token,
			payload: TestPerson{},
			footer:  &TestPerson{},
			error:   ErrDataUnmarshal,
		},
		"Footer unmarshal error": {
			token:   token,
			payload: &TestPerson{},
			footer:  TestPerson{},
			error:   ErrDataUnmarshal,
		},
		"Incorrect sign size": {
			token: "v1.public.eyJOYW1lIjoiSm9obiIsIkF",
			error: ErrIncorrectTokenFormat,
		},
		"Too many token parts": {
			token: "v1.public.eyJOYW1lIj.oiSm9o.biIsIkF",
			error: ErrIncorrectTokenFormat,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := v1.Verify(test.token, rsaPublicKey, test.payload, test.footer)
			assert.Equal(t, test.error, errors.Cause(err))
		})
	}
}
