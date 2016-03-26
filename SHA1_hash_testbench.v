/************************************************************************
* ECE 111
* Final Project
* File: SHA1_hash_testbench.v
* Author: Hao Wang
* Date: April 27, 2010
* Last modified: May 31, 2010
* Version: v6
* Reference: http://en.wikipedia.org/wiki/Sha1
* Email Hao at wanghao@ucsd.edu to report bugs. Thanks.
************************************************************************/

module SHA1_hash_testbench();

reg             clk;
reg             nreset;
reg     [ 31:0] message_addr;

reg     [ 31:0] message_size;
reg     [ 31:0] start_hash;
reg     [ 31:0] port_A_data_out;
reg     [ 31:0] dpsram[0:16383]; // each row has 32 bits

integer         k;
integer         i;
integer         j;
integer         outloop;
integer         cycles;

integer         message_length = 120; // in bytes // change this number to test your design
integer         pad_length;

wire            port_A_clk;
wire    [ 31:0] port_A_data_in;
wire    [ 15:0] port_A_addr;
wire            port_A_we;
wire            done;
wire    [159:0] hash; // results here

reg     [ 31:0] message_seed = 32'h01234567; // modify message_seed to test your design

reg     [159:0] digest_tb;

reg     [ 31:0] h0_tb = 32'h67452301;
reg     [ 31:0] h1_tb = 32'hEFCDAB89;
reg     [ 31:0] h2_tb = 32'h98BADCFE;
reg     [ 31:0] h3_tb = 32'h10325476;
reg     [ 31:0] h4_tb = 32'hC3D2E1F0;

reg     [ 31:0] a_tb;
reg     [ 31:0] b_tb;
reg     [ 31:0] c_tb;
reg     [ 31:0] d_tb;
reg     [ 31:0] e_tb;

reg     [ 31:0] f_tb;
reg     [ 31:0] k_tb;
reg     [ 31:0] temp_tb;

reg     [ 31:0] dpsram_test[0:16383]; // for result testing, testbench only
reg     [ 31:0] w_tb[0:79];

SHA1_hash SHA1_inst (
    .clk             (clk),
    .nreset          (nreset),
    .start_hash      (start_hash[0]),
    .message_addr    (message_addr),
    .message_size    (message_size),
    .hash            (hash),
    .done            (done),
    .port_A_clk      (port_A_clk),
    .port_A_data_in  (port_A_data_in),
    .port_A_data_out (port_A_data_out),
    .port_A_addr     (port_A_addr),
    .port_A_we       (port_A_we)
);

function [31:0] changeEndian; // transform data from the memory to big-endian form (default: little)
    input [31:0] value;
    changeEndian = {value[7:0], value[15:8], value[23:16], value[31:24]};
endfunction

// CLOCK GENERATOR

always begin
    #10;
    clk = 1'b1;
    #10
    clk = 1'b0;
end

// MAIN TESTBENCH

initial
begin
    // RESET HASH CO-PROCESSOR

    @(posedge clk) nreset = 0;
    for (k = 0; k < 2; k = k + 1) @(posedge clk);
    nreset = 1;
    for (k = 0; k < 2; k = k + 1) @(posedge clk);

    // DISPLAY MESSAGETEXT

    $display("-----------\n");
    $display("Messagetext\n");
    $display("-----------\n");

    dpsram[0] = message_seed;
    dpsram_test[0] = changeEndian(message_seed); // change Endian // for testbench only

    $display("%x\n", dpsram[0]);

    for (k = 1; k < (message_length-1)/4+1; k = k + 1) begin // data generation
        dpsram[k] = (dpsram[k-1]<<1)|(dpsram[k-1]>>31);
        dpsram_test[k] = changeEndian(dpsram[k]); // change Endian
        $display("%x\n", dpsram[k]);
    end

    // SET INPUTS TO HASH CO-PROCESSOR

    message_addr = 32'h0;
    message_size = message_length;
    start_hash = 1'b1;
    for (k = 0; k < 2; k = k + 1) @(posedge clk);
    start_hash = 1'b0;

    // testbench results for comparison
    if ( (message_length + 1) % 64 <= 56 && (message_length + 1) % 64 > 0)
        pad_length = (message_length/64)*64 + 56; // calculate total number of bytes after padding (before appending total length)
    else
        pad_length = (message_length/64+1)*64 + 56;

    case (message_length % 4) // pad bit 1
    0: dpsram_test[message_length/4] = 32'h80000000;
    1: dpsram_test[message_length/4] = dpsram_test[message_length/4] & 32'h FF000000 | 32'h 00800000;
    2: dpsram_test[message_length/4] = dpsram_test[message_length/4] & 32'h FFFF0000 | 32'h 00008000;
    3: dpsram_test[message_length/4] = dpsram_test[message_length/4] & 32'h FFFFFF00 | 32'h 00000080;
    endcase

    for (k = message_length/4+1; k < pad_length/4; k = k + 1) begin
        dpsram_test[k] = 32'h00000000;
    end

    dpsram_test[pad_length/4] = message_length >> 29; // append length of the message in bits (before pre-processing)
    dpsram_test[pad_length/4+1] = message_length * 8;
    pad_length = pad_length + 8;                      // final length after pre-processing

    outloop = pad_length/64; // break message into 512-bit chunks (64 bytes)

    for (k = 0; k < outloop; k = k + 1) begin
        for (j = 0; j < 16; j = j + 1) begin
            w_tb[j] = dpsram_test[j+k*16];
        end

        for (j = 16; j < 80; j = j + 1) begin
            w_tb[j] = w_tb[j-3] ^ w_tb[j-8] ^ w_tb[j-14] ^ w_tb[j-16];
            w_tb[j] = (w_tb[j] << 1) | (w_tb[j] >> 31);
        end

        a_tb = h0_tb;
        b_tb = h1_tb;
        c_tb = h2_tb;
        d_tb = h3_tb;
        e_tb = h4_tb;

        for (i = 0; i < 80; i = i + 1) begin
            if (i <= 19) begin
                f_tb = (b_tb & c_tb) | ((b_tb ^ 32'hFFFFFFFF) & d_tb);
                k_tb = 32'h5A827999;
            end else if (i<=39) begin
                f_tb = b_tb ^ c_tb ^ d_tb;
                k_tb = 32'h6ED9EBA1;
            end else if (i<=59) begin
                f_tb = (b_tb & c_tb) | (b_tb & d_tb) | (c_tb & d_tb);
                k_tb = 32'h8F1BBCDC;
            end else begin
                f_tb = b_tb ^ c_tb ^ d_tb;
                k_tb = 32'hCA62C1D6;
            end

            temp_tb = ((a_tb << 5)|(a_tb >> 27)) + f_tb + e_tb + k_tb + w_tb[i];
            e_tb = d_tb;
            d_tb = c_tb;
            c_tb = ((b_tb << 30)|(b_tb >> 2));
            b_tb = a_tb;
            a_tb = temp_tb;
        end

        h0_tb = h0_tb + a_tb;
        h1_tb = h1_tb + b_tb;
        h2_tb = h2_tb + c_tb;
        h3_tb = h3_tb + d_tb;
        h4_tb = h4_tb + e_tb;
    end

    digest_tb = { h0_tb, h1_tb, h2_tb, h3_tb, h4_tb };

    // end of testbench results

    // WAIT UNTIL ENTIRE FRAME IS HASHED, THEN DISPLAY HASH RESULTS

    wait (done == 1);

    // DISPLAY HASH RESULT

    $display("---------------------------\n");
    $display("correct hash result is:\n");
    $display("---------------------------\n");
    $display("%x\n", digest_tb);

    $display("---------------------------\n");
    $display("Your result is:\n");
    $display("---------------------------\n");
    $display("%x\n", hash);

    $display("***************************\n");

    if (digest_tb == hash) begin
        $display("Congratulations! You have the correct hashing result!\n");
        $display("Total number of cycles: %d\n\n", cycles);
        $display("Keep improving your design and also try different input sizes.\n");
        $display("Send Hao your best design before the deadline.\n");
    end else begin
        $display("Error! The hash result is wrong!\n");
    end

    $display("***************************\n");

    $display("EOF\n");

    $stop;
end

// DPSRAM MODEL - (changed on 04/18/03)
// Note (IMPORTANT):
// 1. The HASH Block can access the DPSRAM only word-by-word
//    (and not individual bytes).

// 2. The timing diagrams for reading and writing memory are given
//    on Project1 webpage. Please refer to them.

always @(posedge port_A_clk)
begin
    if (port_A_addr % 4 == 0) begin
        if (port_A_we == 1'b1) // write
            dpsram[port_A_addr >> 2] = port_A_data_in;
        else // read
            port_A_data_out = dpsram[port_A_addr >> 2];
    end else
        $display("Error: memory reference not word aligned!\n");
end

always @(posedge clk) // track # of cycles
begin
    if (!nreset) begin
        cycles = 0;
    end else begin
        cycles = cycles + 1;
    end
end
endmodule