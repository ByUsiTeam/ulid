import argparse
import os
from .core import ULID, ULIDError

def main():
    parser = argparse.ArgumentParser(description="ByUsi ULID Tool")
    subparsers = parser.add_subparsers(dest='command')

    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate ULID')
    gen_parser.add_argument('-u', '--user-data', type=str, 
                           help='Hex string for user data (64 chars)')
    
    # Decode command
    decode_parser = subparsers.add_parser('decode', help='Decode ULID')
    decode_parser.add_argument('ulid', type=str, help='ULID string')

    args = parser.parse_args()

    if args.command == 'generate':
        user_data = os.urandom(32)
        if args.user_data:
            try:
                user_data = bytes.fromhex(args.user_data)
                if len(user_data) != 32:
                    raise ValueError
            except ValueError:
                print("Invalid user data: must be 64 hex chars")
                return
        ulid = ULID.generate(user_data)
        print(ulid.to_string())

    elif args.command == 'decode':
        try:
            decoded = ULID.decode(args.ulid)
            print("Decoded ULID Components:")
            for k, v in decoded.to_dict().items():
                print(f"{k:15}: {v}")
        except ULIDError as e:
            print(f"Decode Error: {str(e)}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()