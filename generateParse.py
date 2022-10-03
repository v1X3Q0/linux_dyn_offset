import argparse
from asyncio import run_coroutine_threadsafe
import json
argparser = argparse.ArgumentParser(description="setting the routines to run on dynamic parsing.")

argparser.add_argument("linux_family",
    help="target linux family")

argparser.add_argument("release_version",
    help="release version for the target")

argparser.add_argument("kernel_version",
    help="kernel version to target.")

argparser.add_argument("heuristic_file",
    help="heuristic json file to determine which functions to call.")

argparser.add_argument("output_file",
    help="generated header name")

def sort_heuristics(json_block, routine_list):
    sorted_heuristics = []
    resolved_list = []

    # pass one, order ones with no dependencies
    while len(routine_list) != 0:
        for routine in routine_list:
            routine_access = json_block[routine]
            for dependency in routine_access['depends']:
                if dependency not in sorted_heuristics:
                    continue
            sorted_heuristics.append(routine)
            for resolution in routine_access['resolves']:
                resolved_list.append(resolution)
            routine_list.remove(routine)
            break

    return sorted_heuristics

def generate_heuristics(heuristic_file, linux_family, release_version, kernel_version):
    routine_list = []
    f = open(heuristic_file, "r")
    json_block = json.load(f)
    f.close()

    for routine in json_block.keys():
        routine_access = json_block[routine]
        if linux_family in routine_access:
            if release_version in routine_access[linux_family]:
                if kernel_version in routine_access[linux_family][release_version]:
                    routine_list.append(routine)
    
    return sort_heuristics(json_block, routine_list)
    

def main():
    args = argparser.parse_args()
    sorted_list = []

    sorted_list = generate_heuristics(args.heuristic_file, args.linux_family, args.release_version, args.kernel_version)

    called_heuristics = "#define RESOLVE_HEURISTICS \\\n"

    for heuristic_index in range(0, len(sorted_list)):
        heuristic = sorted_list[heuristic_index]
        print("--   heuristic stack: {}".format(heuristic))
        each_call = "SAFE_BAIL({}(kernel_local_target) == -1); ".format(heuristic)
        called_heuristics = "{}{}".format(called_heuristics, each_call)
        if heuristic_index != (len(sorted_list) - 1):
            called_heuristics += "\\\n"
        else:
            called_heuristics += "\n"
    
    f = open(args.output_file, "w")
    f.write(called_heuristics)
    f.close()

    return

if __name__ == "__main__":
    main()