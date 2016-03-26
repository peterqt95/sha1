/*
 * SHA-1 final project
 * Names: Derek Tran A10543575
 *	      Peter Tran A11163016
 */
module SHA1_hash (
	clk,
	nreset,
	start_hash,
	message_addr,
	message_size,
	hash,
	done,
	port_A_clk,
   port_A_data_in,
   port_A_data_out,
   port_A_addr,
   port_A_we
	);

input  clk;
input  nreset;
// Initializes the SHA1_hash module

input  start_hash;
// Tells SHA1_hash to start hashing the given frame

input  [31:0] message_addr;
// Starting address of the messagetext frame
// i.e., specifies from where SHA1_hash must read the messagetext frame

input  [31:0] message_size;
// Length of the message in bytes

output [159:0] hash;
// hash results

input  [31:0] port_A_data_out;
// read data from the dpsram (messagetext)

output [31:0] port_A_data_in;
// write data to the dpsram (ciphertext)

output [15:0] port_A_addr;
// address of dpsram being read/written

output port_A_clk;
// clock to dpsram (drive this with the input clk)

output port_A_we;
// read/write selector for dpsram

output done; // done is a signal to indicate that hash  is complete

/**********************
 *
 * FUNCTIONS
 *
 **********************/
//define endian switch function:
function [31:0] changeEndian;
		input [31:0] value;
		changeEndian = { value[7:0], value[15:8], value[23:16], value[31:24]};
endfunction

// left circle shift
function [31:0] leftCircleShift;
	input [31:0] value;
	input [31:0] shiftAmount;
	leftCircleShift = (value << shiftAmount) | (value >> (32 - shiftAmount));
endfunction

/**********************
 *
 * VARIABLES
 *
 **********************/
reg [1:0] STATE;
parameter s_set = 0,
			s_compute = 1,
			s_post = 2,
			s_done = 3;

reg [1:0] READ_STATE;
parameter s_msg = 0,
			s_one = 1,
			s_zero = 2,
			s_length = 3;

reg [1:0] T_STATE;
parameter s_0 = 0,
			s_1 = 1,
			s_2 = 2,
			s_3 = 3;

integer i;

reg [6:0]  t;
reg [15:0] read_addr;
reg [31:0] amount_read;
reg [31:0] W[0:15];
reg [31:0] A, B, C, D, E, F, K, P;
//reg [31:0] H0, H1, H2, H3, H4;

wire [31:0]	word_in, total_length;
wire [15:0]	read_addr_n;
reg [159:0] hash;
reg done;

/**********************
 *
 * ASSIGN
 *
 **********************/
assign port_A_we = 0;
assign port_A_addr = read_addr;
assign port_A_clk = clk;
assign total_length = (message_size * 8) + 1 + 512 - (((8 * message_size) + 65) % 512) + 64;
assign read_addr_n = read_addr + 4;
assign word_in = changeEndian(port_A_data_out);
//assign hash = {H0, H1, H2, H3, H4};

//main logic:
always@(posedge clk or negedge nreset)
begin
	if(!nreset) begin
		//reset all registers
		STATE <= s_set;
		T_STATE <= s_0;
		READ_STATE <= s_msg;

		done <= 0;
		hash <= 0;
	end
	else begin
		case(STATE)
			s_set:
			begin
				if(start_hash) begin
					STATE <= s_compute;
					read_addr <= message_addr[15:0];
					amount_read <= 0;
					t <= 0;

					// initialize to the M values
					hash[159:128] <= 32'h67452301;
					hash[127:96]  <= 32'hefcdab89;
					hash[95:64]   <= 32'h98badcfe;
					hash[63:32]   <= 32'h10325476;
					hash[31:0]    <= 32'hc3d2e1f0;

					A <= 32'h67452301;
					B <= 32'hefcdab89;
					C <= 32'h98badcfe;
					D <= 32'h10325476;
					E <= 32'hc3d2e1f0;

					F <= (32'hefcdab89 & 32'h98badcfe) ^ (~32'hefcdab89 & 32'h10325476);
					P <= leftCircleShift( 32'hefcdab89, 30);
					K <= 32'h5a827999;
				end
			end

			s_compute:
			begin
				t <= t + 1;

				if(t < 16)
				begin
					read_addr <= read_addr + 4;
					amount_read <= amount_read+32;
				end

				if(t < 17)
				begin
					case(READ_STATE)
						s_msg:
						begin
							W[15] <= word_in;								// no padding

							if((message_size  < (amount_read + 32)/8)) READ_STATE <= s_one;
						end

						s_one:
						begin
							case(message_size % 4)          // single bit pad
							0: W[15] <= 32'h80000000;
							1: W[15] <= word_in & 32'hFF000000 | 32'h00800000;
							2: W[15] <= word_in & 32'hFFFF0000 | 32'h00008000;
							3: W[15] <= word_in & 32'hFFFFFF00 | 32'h00000080;
							endcase

							READ_STATE <= s_zero;
						end

						s_zero:
						begin
							W[15] <= 32'h00000000;          // 0 bit pad

							if(amount_read == total_length-32) READ_STATE <= s_length;
						end

						s_length:
						begin
							W[15] <= (message_size * 8);		// message_size pad
						end
					endcase
				end
				else
				begin
					W[15] <= leftCircleShift((W[13] ^ W[8] ^ W[2] ^ W[0]), 1);
				end

				for(i = 0; i < 15; i=i+1)
				begin
					W[i] <= W[i+1];
				end

				if(t > 1)
				begin
					case(T_STATE)
						s_0:
						begin
							K <= 32'h5a827999;
							F <= (A & P) ^ (~A & C);
							if(t == 20) begin T_STATE <= s_1; end
						end

						s_1:
						begin
							K <= 32'h6ed9eba1;
							F <= A ^ P ^ C;
							if(t == 40) begin T_STATE <= s_2; end
						end

						s_2:
						begin
							K <= 32'h8f1bbcdc;
							F <= (A & P) ^ (A & C) ^ (P & C);
							if(t == 60) begin T_STATE <= s_3; end
						end

						s_3:
						begin
							K <= 32'hca62c1d6;
							F <=  A ^ P ^ C;
							if(t == 81) begin T_STATE <= s_0; end
						end
					endcase

					A <= ((A << 5) | (A >> 27)) + F + W[15] + K + E;
					B <= A;
					C <= P;
					D <= C;
					E <= D;

					P <= leftCircleShift(A, 30);
					if(t == 81)
					begin
						STATE <= s_post;
					end
				end
			end

			s_post:
			begin
				t <= 0;

				hash[159:128] <= hash[159:128] + A;
				hash[127:96]  <= hash[127:96]  + B;
				hash[95:64]   <= hash[95:64]   + C;
				hash[63:32]   <= hash[63:32]   + D;
				hash[31:0]    <= hash[31:0]    + E;

				A <= hash[159:128] + A;
				B <= hash[127:96]  + B;
				C <= hash[95:64]   + C;
				D <= hash[63:32]   + D;
				E <= hash[31:0]    + E;

				F <= ((hash[127:96] + B) & (hash[95:64] + C)) ^ (~(hash[127:96] + B) & (hash[63:32] + D));
				P <= leftCircleShift((hash[127:96] + B), 30);
				K <= 32'h5a827999;

				if(amount_read >= total_length)
				begin
					STATE <= s_done;
				end
				else
				begin
					STATE <= s_compute;
				end
			end

			s_done:
			begin
				done <= 1;
			end
		endcase
	end
end
endmodule