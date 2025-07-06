import sys
import os

def generate_c_byte_array(input_file, output_file):
    # Use the base file name to create a valid C identifier
    base_name = os.path.basename(input_file)
    name = os.path.splitext(base_name)[0]
    c_array_name = name.replace('.', '_').replace('-', '_')

    with open(input_file, 'rb') as f:
        data = f.read()

    with open(output_file, 'w') as out:
        out.write(f"// Auto-generated from {input_file}\n")
        out.write("#include <stddef.h>\n\n")
        out.write(f"const unsigned char {c_array_name}[] = {{\n")

        for i, byte in enumerate(data):
            if i % 12 == 0:
                out.write("    ")
            out.write(f"0x{byte:02x}, ")
            if (i + 1) % 12 == 0:
                out.write("\n")

        out.write("\n};\n")
        out.write(f"const unsigned int {c_array_name}_len = {len(data)};\n")

    print(f"Generated {output_file} with array '{c_array_name}' of length {len(data)}.")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_file> <output_file.c>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    generate_c_byte_array(input_file, output_file)
