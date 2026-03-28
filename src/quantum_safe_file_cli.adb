with Ada.Text_IO;            use Ada.Text_IO;
with Ada.Characters.Latin_1; use Ada.Characters.Latin_1;
with Ada.Command_Line;       use Ada.Command_Line;
with Ada.Exceptions;         use Ada.Exceptions;
with Ada.Streams.Stream_IO;
with GNAT.OS_Lib;            use GNAT.OS_Lib;

procedure Quantum_Safe_File_CLI is

   Max_Len : constant Positive := 1024 * 10;   -- support up to 10 KB

   type Message_Type is array (Positive range <>) of Character;

   -- ====================== HELPER ======================
   procedure Run_Helper (Command : String) is
      Args    : Argument_List (1 .. 1);
      Success : Boolean;
   begin
      Args (1) := new String'(Command);
      Spawn
        (Program_Name => "./mlkem_helper", Args => Args, Success => Success);

      if not Success then
         Put_Line
           ("ERROR: Failed to run mlkem_helper with command: " & Command);
         raise Program_Error;
      end if;
   end Run_Helper;

   -- ====================== BINARY FILE I/O ======================
   procedure Save_To_File
     (Filename : String; Data : Message_Type; Len : Natural)
   is
      F      : Ada.Streams.Stream_IO.File_Type;
      Stream : Ada.Streams.Stream_IO.Stream_Access;
   begin
      Ada.Streams.Stream_IO.Create
        (F, Ada.Streams.Stream_IO.Out_File, Filename);
      Stream := Ada.Streams.Stream_IO.Stream (F);
      for I in 1 .. Len loop
         Character'Write (Stream, Data (I));
      end loop;
      Ada.Streams.Stream_IO.Close (F);
   end Save_To_File;

   procedure Load_From_File
     (Filename : String; Data : out Message_Type; Len : out Natural)
   is
      F      : Ada.Streams.Stream_IO.File_Type;
      Stream : Ada.Streams.Stream_IO.Stream_Access;
      C      : Character;
      Index  : Positive := 1;
   begin
      Ada.Streams.Stream_IO.Open (F, Ada.Streams.Stream_IO.In_File, Filename);
      Stream := Ada.Streams.Stream_IO.Stream (F);
      while not Ada.Streams.Stream_IO.End_Of_File (F) and Index <= Max_Len loop
         Character'Read (Stream, C);
         Data (Index) := C;
         Index := Index + 1;
      end loop;
      Len := Index - 1;
      Ada.Streams.Stream_IO.Close (F);
   end Load_From_File;

   -- ====================== To_String (FIXED) ======================
   function To_String (M : Message_Type; Len : Natural) return String is
      S : String (1 .. Len);
   begin
      for I in 1 .. Len loop
         S (I) := M (I);
      end loop;
      return S;
   end To_String;

   -- Buffers
   Plain   : Message_Type (1 .. Max_Len);
   Cipher  : Message_Type (1 .. Max_Len);   -- not used directly now
   Decoded : Message_Type (1 .. Max_Len);
   Len     : Natural := 0;

begin
   if Argument_Count < 1 then
      Put_Line ("Usage:");
      Put_Line ("  ./quantum_safe_file_cli encrypt");
      Put_Line ("  ./quantum_safe_file_cli decrypt");
      return;
   end if;

   declare
      Mode : constant String := Argument (1);
   begin
      if Mode = "encrypt" then
         Put ("Enter your message (max ~10 KB): ");
         declare
            Input_Line : constant String := Get_Line;
            Actual_Len : constant Natural :=
              Natural'Min (Input_Line'Length, Max_Len);
         begin
            if Actual_Len = 0 then
               Put_Line ("No input entered.");
               return;
            end if;

            Len := Actual_Len;
            Plain (1 .. Len) := Message_Type (Input_Line (1 .. Len));

            -- Save plaintext for the C helper
            Save_To_File ("message.bin", Plain, Len);

            -- Hybrid Post-Quantum Encryption: ML-KEM + AES-256-GCM
            Run_Helper ("keygen");      -- only needed first time
            Run_Helper ("encrypt");

            Put_Line ("✅ Hybrid Quantum-Safe Encryption Complete!");
            Put_Line
              ("   ML-KEM-768 (key transport) + AES-256-GCM (data + integrity tag)");
            Put_Line ("   Encrypted file saved as: cipher.bin");
         end;

      elsif Mode = "decrypt" then
         -- Hybrid Post-Quantum Decryption
         Run_Helper ("decrypt");

         declare
            Dec_Len : Natural;
         begin
            Load_From_File ("decrypted.bin", Decoded, Dec_Len);

            if Dec_Len > 0 then
               Put_Line ("Decrypted message:");
               Put_Line (To_String (Decoded, Dec_Len));
            else
               Put_Line ("Decryption returned empty message.");
            end if;
         end;

      else
         Put_Line ("Unknown mode. Use 'encrypt' or 'decrypt'.");
      end if;
   end;

exception
   when E : others =>
      Put_Line
        ("Unexpected error: "
         & Exception_Name (E)
         & " - "
         & Exception_Message (E));
end Quantum_Safe_File_CLI;
