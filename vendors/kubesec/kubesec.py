import itertools
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterator, Literal, Optional, Union

import jmespath
import thefuzz
import yaml
from jsonpath_ng.ext import parse

from ..base_vendor import BaseVendor

class KubeSecResult:
    def __init__(self, id: str, selector: str, reason: str, points: int):
        self.id = id
        self.selector = selector
        self.reason = reason
        self.points = points

    def __repr__(self):
        return self.__dict__.__repr__()

    @classmethod
    def from_dict(cls, **data_dict):
        return cls(**data_dict)

class KubeSec(BaseVendor):
    def __init__(self):
        super().__init__("kubesec")
        self.rules = self.load_rules()
        self.config = None
        self.cur_result = dict()
        self.prev_result = dict()
        self.pathes = self.get_pathes()
        self.comparison_operators = ["==", "-gt", "-lt", "-ge", "-le"]
        self.full_operators = self.comparison_operators + ["contains"]
        self.assets_dir = "assets/kubesec"

    def __call__(self, config):
        return self.fix(config)

    def _scan(self, config: Iterator[Any]) -> Dict[Any, Any]:
        def _extract_result(output, level: Literal["critical", "advise"]):
            assert len(output) == 1, "There should be only one output"
            result = jmespath.search(f"scoring.{level}", output[0])
            return result if result else []
        try:
            tmp_path = self.generate_tempfile(config, "yaml")
            with open(tmp_path, "r") as f:
                self.config = yaml.load_all(f.read(), Loader=yaml.FullLoader)
            scan_output = subprocess.run([f"{self.name}", "scan", tmp_path, "-f", "json"], capture_output=True)
            cur_output = json.loads(scan_output.stdout.decode("utf-8"))
            self.raw_output = cur_output
            if self.cur_result:
                self.prev_result = self.cur_result
            self.cur_result["critical"] = [KubeSecResult.from_dict(**result) for result in _extract_result(cur_output, "critical")]
            self.cur_result["advise"] = [KubeSecResult.from_dict(**result) for result in _extract_result(cur_output, "advise")]
            os.remove(tmp_path)
            return self.cur_result
        except Exception as e:
            raise e
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def update(self, rules_filename="kubesec_rules.json"):
        os.system(f"kubesec print-rules -f json > {os.path.join(self.assets_dir,rules_filename)}")

    def scan(self, config: Union[str, Iterator[Any]]):
        def _get_value(input_str):
            def _extract(_str, mode):
                return tuple([".".join([_item.strip() for _item in item.strip().split(".")]) for item in _str.split(mode)]) + (mode,)
            for operator in self.comparison_operators:
                if operator in input_str:
                    return _extract(input_str, operator)
            return tuple([".".join([item.strip() for item in input_str.split(".")]), None]) + (None,)

        def _make_selector(lhs, rhs, mode):
            return {"lhs": lhs, "rhs": rhs, "mode": mode}
        if isinstance(config, str):
            if os.path.exists(config):
                _config = self.read_yaml_from_file(config)
            else:
                _config = self.read_yaml_from_str(config)
            self._scan(_config)
        else:
            self._scan(config)

        final_results = []
        for level, results in self.cur_result.items():
            for idx, result in enumerate(results):
                id = result.id
                sub_res = []
                selector = result.selector
                pipe = [p.strip() for p in selector.split("|")]
                match len(pipe):
                    case 2:
                        args = [p.strip() for p in pipe[0].split(",")]
                        if pipe[1].startswith("index("):
                            pipe[1] = re.findall(r'index\("([^"]+)"\)', pipe[1])
                            lhs, _, _ = _get_value(pipe[0])
                            rhs = pipe[1]
                            mode = "contains"
                            if len(args) == 1:
                                sub_res.append(_make_selector(lhs, rhs, mode))
                            else:
                                for pre, (lhs, rhs, mode) in itertools.product(args, [(lhs, rhs, mode)]):
                                    sub_res.append(_make_selector(pre + lhs, rhs, mode))
                        else:
                            lhs, rhs, mode = _get_value(pipe[1])
                            for pre, (lhs, rhs, mode) in itertools.product(args, [(lhs, rhs, mode)]):
                                sub_res.append(_make_selector(pre + lhs, rhs, mode))
                    case 1:
                        lhs, rhs, mode = _get_value(pipe[0])
                        sub_res.append(_make_selector(lhs, rhs, mode))
                    case _:
                        raise ValueError("Invalid selector")
                if sub_res:
                    sub_res = {"levle": level, "index": idx, "id": id, "sels": sub_res, "reason": result.reason}
                    final_results.append(sub_res)
        return final_results

    def load_rules(self, rules_filename="kubesec_rules.json"):
        if not os.path.exists(abs_filepath := os.path.join(Path(__file__).parent, rules_filename)):
            os.system(f"kubesec print-rules -f json > {abs_filepath}")
        with open(abs_filepath, "r") as f:
            return json.load(f)

    def get_pathes(self, obj: Optional[Any] = None):
        if not self.flatten:
            self.flatten = self.get_flatten(obj)
        self.pathes = list(set([re.sub(r"\[.*?\]", "[*]", key) for key in self.flatten.keys()]))
        return self.pathes

    def get_flatten(self, obj: Optional[Any] = None):
        if obj:
            return super().get_flatten(obj)
        else:
            return self.flatten_json(self.config)

    def fix(self, config):
        return self._fix(config)

    def _fix(self, test):
        def find_depths(data, target, depth=0, depths=None):
            if depths is None:
                depths = []

            if isinstance(data, dict):
                for key, value in data.items():
                    if key == target:
                        depths.append(depth)
                    find_depths(value, target, depth + 1, depths)
            elif isinstance(data, list):
                for item in data:
                    find_depths(item, target, depth, depths)
            elif data == target:
                depths.append(depth)

            return list(set(sorted(depths)))

        def split_sel(sel):
            start_with_dot = sel.startswith(".")
            _sel = sel if not start_with_dot else sel[1:]
            pattern_quotes = r'".*?"'
            matches_quotes = re.findall(pattern_quotes, _sel)
            assert len(matches_quotes) <= 1, f"more than one match: {matches_quotes}"
            matches_no_quotes = (_sel.replace("." + matches_quotes[0], "") if len(matches_quotes) == 1 else _sel).split(".")
            assert len(matches_no_quotes) >= 1
            return matches_no_quotes + matches_quotes, start_with_dot, False if len(matches_quotes) == 1 else True

        def list_to_nested_dict(lst, last_value="Nan"):
            lst = [i.replace('"', "") if i.startswith('"') else i for i in lst]
            nested_dict = current_level = {}
            for item in lst[:-1]:
                current_level[item] = {}
                current_level = current_level[item]
            current_level[lst[-1]] = last_value
            return nested_dict

        def update_missings(input_data, query, desired):
            input_data_c = input_data.copy()
            jsExp = parse(query)
            for match in jsExp.find(input_data_c):
                path = match.path
                current_value = match.value
                if isinstance(current_value, dict):
                    current_value.update(desired)
                    path.update(desired, current_value)
                # elif current_value is None:
                #     return update_missings(input_data, ".".join(query.split(".")[:-1]), desired)
            return input_data_c
        scaned_res = self.scan(test)
        failed = []
        for item in scaned_res:
            for sel in item["sels"]:
                if sel["rhs"] == "true":
                    rhs = True
                elif sel["rhs"] == "false":
                    rhs = False
                else:
                    if sel["rhs"] and not isinstance(sel["rhs"], list) and sel["rhs"].isdigit():
                        rhs = int(sel["rhs"])
                    else:
                        rhs = sel["rhs"]
                if sel["lhs"].endswith(".capabilities.add"):
                    sel["mode"] = "contains"
                    rhs = [rhs]
                lhs = sel["lhs"]
                mode = sel["mode"]
                lhs_lst, start_with_dot, has_phrase = split_sel(lhs)
                lhs_t_lst = ["list" if "[]" in i else "dict" for i in lhs_lst[:-1]]
                lhs_t_lst += ["list" if "[]" in lhs_t_lst[-1] and not has_phrase else "dict"]
                _head = lhs_lst[0]
                depths = find_depths(test, _head)

                query = ("$." if start_with_dot else "$..") + lhs.replace("[]", "[*]")
                jsExp = parse(query)
                matches = jsExp.find(test)
                matches_path = [str(m.full_path) for m in matches] if len(matches) >= 1 else None
                if (rhs is not None) and mode and matches:
                    match mode:
                        case "==":
                            test = jsExp.update(test, not rhs)
                        case "-ge" | "-le":
                            test = jsExp.update(test, int(rhs))
                        case "-gt":
                            test = jsExp.update(test, int(rhs) + 1)
                        case "-lt":
                            test = jsExp.update(test, int(rhs) - 1)
                        case "contains":
                            test = jsExp.update(test, rhs)
                    break
                else:
                    def query_iter(lhs_lst, lhs_t_lst, data, traveled=[]):
                        _query = "$.."
                        for item, type in zip(lhs_lst, lhs_t_lst):
                            if type == "list":
                                _query += item.replace("[]", "[*]")
                            else:
                                _query += item
                            _query += "."
                        _query = _query[:-1]
                        jsExp = parse(_query)
                        matches = jsExp.find(data)
                        if matches:
                            return [str(m.full_path) for m in matches], traveled, _query
                        else:
                            if len(lhs_lst) == 1 and len(lhs_t_lst) == 1:
                                return None, traveled, _query
                            else:
                                traveled = [lhs_lst[-1]] + traveled
                                return query_iter(lhs_lst[:-1], lhs_t_lst[:-1], data, traveled)
                    # print(lhs,":::",rhs,":::",mode,":::", lhs_lst)
                    res, traveled, query = query_iter(lhs_lst, lhs_t_lst, test)
                    if res:
                        for _res in res:
                            desired = list_to_nested_dict(traveled, rhs if (rhs is not None) else "_placeholder")
                            for k, v in desired.items():
                                if k == "cpu" or k == "memory":
                                    desired[k] = "0"

                            test = update_missings(test, _res, desired)
                            # print(test)
                    else:
                        failed.append((item, sel))
                continue
        return test
