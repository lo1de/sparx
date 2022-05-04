#include<iostream>
#include<iomanip>

//#define DEBUG
#define SPARX64_KEY_LENGTH          16
#define SPARX64_STATE_LENGTH         8
#define SPARX64_NUM_KEY_WORDS        8
#define SPARX64_NUM_STATE_WORDS      4

#define SPARX_L               L2
#define SPARX_L_INV           L2_inverse
#define SPARX_KEY_PERMUTATION K_perm_64_128

#define ROTL16(x, n) (((x) << n) | ((x) >> (16 - (n))))
#define ROTR16(x, n) (((x) >> n) | ((x) << (16 - (n))))
#define SWAP(x, y) tmp = x; x = y; y = tmp

using namespace std;

static size_t NUM_STEPS = 8;
static size_t NUM_ROUNDS_PER_STEP = 3;
static const size_t NUM_BRANCHES = 2;

typedef struct {
	uint16_t subkeys[17][2 * 3];
} sparx64_context_t;

void A(uint16_t* l, uint16_t* r) {
	(*l) = ROTR16((*l), 7);
	(*l) += (*r);
	(*r) = ROTL16((*r), 2);
	(*r) ^= (*l);
}

void A_inverse(uint16_t* l, uint16_t* r)
{
	(*r) ^= (*l);
	(*r) = ROTR16((*r), 2);
	(*l) -= (*r);
	(*l) = ROTL16((*l), 7);
}

void K_perm_64_128(uint16_t* key, const uint16_t round) {
	uint16_t tmp0;
	uint16_t tmp1;
	uint16_t i;

	/*for (int i = 0; i < 6; ++i)
		cout << hex << key[i] << " ";

	cout << endl;*/

	// Misty-like transformation
	A(key + 0, key + 1);
	key[2] += key[0];
	key[3] += key[1];
	key[7] += round;

	// Branch rotation
	tmp0 = key[6];
	tmp1 = key[7];

	for (i = 7; i >= 2; i--) {
		key[i] = key[i - 2];
	}

	key[0] = tmp0;
	key[1] = tmp1;
}

void print_hex(const uint16_t* array, const size_t num_words) 
{
	for (size_t i = 0; i < num_words; i++) 
	{
		cout << setfill('0') << setw(4) << hex << array[i] << " ";
	}
	
	cout << endl;
}

static void L2(uint16_t* state) {
	uint16_t tmp = state[0] ^ state[1];
	tmp = ROTL16(tmp, 8);
	state[2] ^= state[0] ^ tmp;
	state[3] ^= state[1] ^ tmp;

	SWAP(state[0], state[2]);
	SWAP(state[1], state[3]);
}

// ---------------------------------------------------------

static void L2_inverse(uint16_t* state) {
	uint16_t tmp;

	SWAP(state[0], state[2]);
	SWAP(state[1], state[3]);

	tmp = state[0] ^ state[1];
	tmp = ROTL16(tmp, 8);
	state[2] ^= state[0] ^ tmp;
	state[3] ^= state[1] ^ tmp;
}

void sparx_key_schedule(sparx64_context_t* ctx,
	const uint16_t master_key[SPARX64_NUM_KEY_WORDS]) {

	uint16_t key[SPARX64_NUM_KEY_WORDS];
	memcpy((uint8_t*)key, (uint8_t*)master_key, SPARX64_KEY_LENGTH);

	const size_t NUM_ROUND_KEYS = NUM_BRANCHES * NUM_STEPS + 1;

	for (size_t c = 0; c < NUM_ROUND_KEYS; c++) {
		for (size_t i = 0; i < 2 * NUM_ROUNDS_PER_STEP; i++) {
			ctx->subkeys[c][i] = key[i];

#ifdef DEBUG
			/*printf("Branch/round: %2zu/%2zu ", c, i);*/
			print_hex(&(ctx->subkeys[c][i]), 1);
#endif
		}

		SPARX_KEY_PERMUTATION(key, c + 1);
	}
}

static void sparx_encrypt_steps(const sparx64_context_t* ctx, uint16_t state[SPARX64_NUM_STATE_WORDS], const size_t from_step, const size_t to_step) 
{
	for (size_t s = from_step - 1; s < to_step; ++s) {
		for (size_t b = 0; b < NUM_BRANCHES; ++b) {
			for (size_t r = 0; r < NUM_ROUNDS_PER_STEP; ++r) {
				state[2 * b] ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r];
				state[2 * b + 1] ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r + 1];
				A(state + 2 * b, state + 2 * b + 1);

#ifdef DEBUG
				printf("Branch/round: %2zu/%2zu ", b, r);
				print_hex(state, 8);
				cout << endl;
#endif
			}
		}

		SPARX_L(state);

#ifdef DEBUG
		puts("After L");
		print_hex(state, 4);
		cout << endl;
#endif
	}

	if (to_step == NUM_STEPS) {
		for (size_t b = 0; b < NUM_BRANCHES; ++b) {
			state[2 * b] ^= ctx->subkeys[NUM_BRANCHES * NUM_STEPS][2 * b];
			state[2 * b + 1] ^= ctx->subkeys[NUM_BRANCHES * NUM_STEPS][2 * b + 1];
		}
	}

	cout << "Encrypted:" << endl;
	print_hex(state, 4);
}

void sparx_encrypt_steps(const sparx64_context_t* ctx, const uint16_t p[SPARX64_NUM_STATE_WORDS], uint16_t c[SPARX64_NUM_STATE_WORDS], const size_t num_steps)
{
	memcpy((uint8_t*)c, (uint8_t*)p, SPARX64_STATE_LENGTH);
	sparx_encrypt_steps(ctx, c, 1, num_steps);
}

void sparx_encrypt(const sparx64_context_t* ctx, const uint16_t p[SPARX64_STATE_LENGTH], uint16_t c[SPARX64_STATE_LENGTH])
{
	sparx_encrypt_steps(ctx, p, c, NUM_STEPS);
}

static void sparx_decrypt_steps(const sparx64_context_t* ctx,
	uint16_t state[SPARX64_NUM_STATE_WORDS],
	const size_t from_step,
	const size_t to_step) {
	if (to_step == NUM_STEPS) {
		for (size_t b = 0; b < NUM_BRANCHES; ++b) {
			state[2 * b] ^= ctx->subkeys[NUM_BRANCHES * NUM_STEPS][2 * b];
			state[2 * b + 1] ^= ctx->subkeys[NUM_BRANCHES * NUM_STEPS][2 * b + 1];
		}
	}

	const int last_step = (int)from_step - 1;

	for (int s = to_step - 1; s >= last_step; --s) {
		SPARX_L_INV(state);

		for (size_t b = 0; b < NUM_BRANCHES; ++b) {
			for (int r = NUM_ROUNDS_PER_STEP - 1; r >= 0; --r) {
				A_inverse(state + 2 * b, state + 2 * b + 1);
				state[2 * b] ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r];
				state[2 * b + 1] ^= ctx->subkeys[s * NUM_BRANCHES + b][2 * r + 1];
			}
		}
	}

	cout << "Decrypted:" << endl;
	print_hex(state, 4);
}

void sparx_decrypt_steps(const sparx64_context_t* ctx,
	const uint16_t c[SPARX64_NUM_STATE_WORDS],
	uint16_t p[SPARX64_NUM_STATE_WORDS],
	const size_t num_steps) {
	memcpy((uint8_t*)p, (uint8_t*)c, SPARX64_STATE_LENGTH);
	sparx_decrypt_steps(ctx, p, 1, num_steps);
}

void sparx_decrypt(const sparx64_context_t* ctx,
	const uint16_t c[SPARX64_STATE_LENGTH],
	uint16_t p[SPARX64_STATE_LENGTH]) {
	sparx_decrypt_steps(ctx, c, p, NUM_STEPS);
}

void test()
{
	//uint16_t master_key[] = {0x0011, 0x2233, 0x4455, 0x6677, 0x8899, 0xaabb, 0xccdd, 0xeeff};
	uint16_t master_key[] = { 0x718d,0x1ebe,0x75cb,0x4a38,0x1fe5,0x46f3,0x36b8,0x610d };
	cout << "Key:" << endl;
	print_hex(master_key, 8);

	//uint16_t plaintext[] = {0x0123, 0x4567, 0x89ab, 0xcdef};
	uint16_t plaintext[] = { 0x3bd8,0xa08,0x7ff3,0x482d };
	cout << "Text to encrypt:" << endl;
	print_hex(plaintext, 4);

	sparx64_context_t ctx;
	sparx_key_schedule(&ctx, master_key);

	uint16_t c[SPARX64_STATE_LENGTH];
	sparx_encrypt(&ctx, plaintext, c);

	sparx_decrypt(&ctx, c, plaintext);
}

void input(uint16_t* array, const size_t num_words)
{
	for (size_t i = 0; i < num_words; i++)
	{
		cin >> hex >> array[i];
	}
}

void enter_data()
{
	uint16_t master_key[8];
	cout << "Enter key 8 16 bit hex words:" << endl;
	input(master_key, 8);

	uint16_t plaintext[4];
	cout << "Enter key 4 16 bit hex words:" << endl;
	input(plaintext, 4);

	sparx64_context_t ctx;
	sparx_key_schedule(&ctx, master_key);

	uint16_t c[SPARX64_STATE_LENGTH];
	sparx_encrypt(&ctx, plaintext, c);

	sparx_decrypt(&ctx, c, plaintext);
}

int main()
{
	int variant;
	cout << "Want to enter your own text or use the prepared" << endl;
	cout << "1. Own text" << endl;
	cout << "2. Prepared text" << endl << endl;
	cout << "Enter number 1 or 2: ";
	cin >> variant;

	cout << endl;
	cout << "Enter the number of steps" << endl;
	cin >> NUM_STEPS;
	cout << "Enter the number of rounds per step" << endl;
	cin >> NUM_ROUNDS_PER_STEP;

	if (variant == 2)
	{
		test();
	}
	else
	{
		enter_data();
	}

	system("pause");

	return 0;
}