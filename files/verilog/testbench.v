`include "_c_opt.v"
`include "uart.v"

`timescale 1ns/100ps

module challenge_tb;

    reg r_clk = 0;
    reg r_reset_line = 0;
    reg r_tx_data_valid = 0;
    reg [7:0] r_tx_byte = 0;

    wire w_uart_tx; // tx is the xmit of the DUT, and the rx of the TB.
    wire w_uart_rx; // rx is the recv of the DUT, and the tx of the TB.

    wire w_tx_active;
    wire w_tx_data;
    wire [7:0] w_rx_byte;
    wire w_rx_data_valid;

    wire w_tx_done;

    integer fd_stdin;
    integer fd_outfile;
    integer i, j, status;
    integer data;

    parameter _CLK_PERIOD = 42;    // (1/12e6)/1ns = 83.33; is approx 12MHz main sysclock.
    parameter _CLKS_PER_BIT = 104; // 12e6 / 115200 = 104,166
    parameter _BIT_PERIOD = 3468;  // (1/115220) / 1ns = 8680 ticks.

    initial begin
        r_clk <= 0;
        r_reset_line <= 1;
    end

    always #_CLK_PERIOD r_clk <= !r_clk;

    // If not tx active, then uart_rx (the tx of this TB) is set to always 1
    // (UART default state)
    assign w_uart_rx = w_tx_active ? w_tx_data : 1'b1;

    top DUT_Inst (
        .MIB_R0C40_PIOT0_PADDOA_PIO(w_uart_tx),
        .MIB_R0C40_PIOT0_JPADDIB_PIO(w_uart_rx),
        .MIB_R0C60_PIOT0_JPADDIA_PIO(r_reset_line),
        .G_HPBX0000(r_clk)
    );

    UART_TX #(.CLKS_PER_BIT(_CLKS_PER_BIT)) UART_TX_Inst (
        .i_Clock(r_clk),
        .i_TX_DV(r_tx_data_valid),
        .i_TX_Byte(r_tx_byte),
        .o_TX_Active(w_tx_active),
        .o_TX_Serial(w_tx_data),
        .o_TX_Done(w_tx_done)
    );

    UART_RX #(.CLKS_PER_BIT(_CLKS_PER_BIT)) UART_RX_Inst (
        .i_Clock(r_clk),
        .i_RX_Serial(w_uart_tx),
        .o_RX_DV(w_rx_data_valid),
        .o_RX_Byte(w_rx_byte)
    );

    // Main/TX procedure
    initial begin
        // Reset the DUT device at the start.
        r_reset_line <= 0;
        #10_000; // 10µs delay
        r_reset_line <= 1;
        #10_000; // 10µs delay

        // Open stdin in order to read bytes to transmit to the DUT.
        fd_stdin = $fopen("/proc/self/fd/0", "r");
        if (fd_stdin == 0) $error("Cannot open /proc/self/fd/0 (stdin)");

        // Transmit 8 bytes over UART.
        for (i=0; i < 8; i = i+1)
        begin
            status = $fscanf(fd_stdin, "%x", data);
            @(posedge r_clk);
            @(posedge r_clk);
            r_tx_data_valid <= 1'b1;
            r_tx_byte <= data[7:0];
            @(posedge r_clk);
            r_tx_data_valid <= 1'b0;

            $display("PC -> FPGA: 0x%x", r_tx_byte);
            // Wait for TX to be done before sending next byte.
            @(posedge w_tx_done);
            #_BIT_PERIOD;
        end

        // Transmission now done. We wait for 8 bytes from the FPGA.
        $display("=== FPGA DATA BEGIN ===");
    end

    // RX procedure
    initial begin

        // Recieve 8 bytes.
        for (j = 0; j < 8; j = j+1)
        begin
            @(posedge w_rx_data_valid);
            $display("%x ", w_rx_byte);
        end

        $finish();
    end

    // 80ms timeout trap.
    initial begin
        #80_000_000;
        $display("Timeout trap reached. Terminating simulation.");
        $finish();
    end

    // Configure the simulator to output wave data to dump.vcd.
    initial begin
        $dumpfile("dump.vcd");
        $dumpvars;
    end

endmodule