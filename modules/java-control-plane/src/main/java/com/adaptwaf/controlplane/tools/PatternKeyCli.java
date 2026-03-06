package com.adaptwaf.controlplane.tools;

import com.adaptwaf.controlplane.service.PatternKeyService;

/**
 * pattern_key_v1 命令行工具。
 * 说明：仅依赖 JDK + PatternKeyService，用于跨语言契约校验。
 */
public final class PatternKeyCli {

    private PatternKeyCli() {
    }

    /**
     * CLI 入口。
     *
     * @param args method routeKey contentType surface fieldName jsonPath detector signature
     */
    public static void main(String[] args) {
        if (args.length < 8) {
            System.err.println(
                    "usage: PatternKeyCli <method> <route_key> <content_type> <surface> <field_name> <json_path> <detector> <signature>"
            );
            System.exit(1);
            return;
        }

        String result = PatternKeyService.buildPatternKeyV1(
                args[0],
                args[1],
                args[2],
                args[3],
                args[4],
                args[5],
                args[6],
                args[7]
        );
        System.out.println(result);
    }
}
