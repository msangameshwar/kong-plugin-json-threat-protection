local plugin = {
  PRIORITY = 998, -- set the plugin priority, which determines plugin execution order
  VERSION = "0.1", -- version in X.Y.Z format. Check hybrid-mode compatibility requirements.
}

function plugin:access(config)
  local function json_threat_protection()
        local cjson = require("cjson")
        local cjson_safe = require("cjson.safe")

        local initialRequest = kong.request.get_raw_body()
        local content_type = kong.request.get_header("content-type")
        local request_method = kong.request.get_method()

        local function is_array(table)
            local max = 0
            local count = 0
            for k, v in pairs(table) do
                if type(k) == "number" then
                    if k > max then max = k end
                    count = count + 1
                else
                    return -1
                end
            end
            if max > count * 2 then
                return -1
            end

            return max
        end

        local function validateJson(json, array_element_count, object_entry_count, object_entry_name_length, string_value_length)
            if type(json) == "table" then
                if array_element_count > 0 then
                    local array_children = is_array(json)
                    if array_children > array_element_count then
                        local error_message = "JSONThreatProtection[ExceededArrayElementCount]: Exceeded array element count, max " .. array_element_count .. " allowed, found " .. array_children .. "."
                        return kong.response.error(400, error_message, {
                            ["Content-Type"] = "application/json"
                        })
                    end
                end

                local children_count = 0
                for k,v in pairs(json) do
                    children_count = children_count + 1
                    if object_entry_name_length > 0 then
                        if string.len(k) > object_entry_name_length then
                            local error_message = "JSONThreatProtection[ExceededObjectEntryNameLength]: Exceeded object entry name length, max " .. object_entry_name_length .. " allowed, found " .. string.len(k) .. " (" .. k .. ")."
                            return kong.response.error(400, error_message, {
                                ["Content-Type"] = "application/json"
                            })
                        end
                    end

                    local result, message = validateJson(v, array_element_count, object_entry_count, object_entry_name_length, string_value_length)
                    if result == false then
                        return false, message
                    end
                end

                if object_entry_count > 0 then
                        if children_count > object_entry_count and is_array(json) == -1 then
                        local error_message = "JSONThreatProtection[ExceededObjectEntryCount]: Exceeded object entry count, max " .. object_entry_count .. " allowed, found " .. children_count .. "."
                        return kong.response.error(400, error_message, {
                            ["Content-Type"] = "application/json"
                        })
                    end
                end

            else
                if string_value_length > 0 then
                    if string.len(json) > string_value_length then
                        local error_message = "JSONThreatProtection[ExceededStringValueLength]: Exceeded string value length, max " .. string_value_length .. " allowed, found " .. string.len(json) .. " (" .. json .. ")."
                        return kong.response.error(400, error_message, {
                            ["Content-Type"] = "application/json"
                        })
                    end
                end
            end
        end

        local function JsonValidator(body, container_depth, array_element_count, object_entry_count, object_entry_name_length, string_value_length)

            local valid = cjson_safe.decode(body)
            if not valid then
                local error_message = "JSONThreatProtection[InvalidData]: Received invalid/null data."
                return kong.response.error(400, error_message, {
                    ["Content-Type"] = "application/json"
                })
            end

            if container_depth > 0 then
                cjson.decode_max_depth(container_depth)
            end

            local status, json = pcall(cjson.decode, body)

            if not status then
                local error_message = "JSONThreatProtection[ExceededContainerDepth]: Exceeded container depth, max " .. container_depth .. " allowed."
                return kong.response.error(400, error_message, {
                    ["Content-Type"] = "application/json"
                })
            end
            local depth_flag = true
            for key, value in pairs(json) do
                    depth_flag = false
                    break
            end
            if depth_flag then
                local error_message = "JSONThreatProtection[EmptyString]: Received empty string."
                return kong.response.error(400, error_message, {
                    ["Content-Type"] = "application/json"
                })
            end
            validateJson(json, array_element_count, object_entry_count, object_entry_name_length, string_value_length)
        end

        if content_type then
            if string.match(content_type, "application/json") and  request_method ~= "GET" then
                JsonValidator(initialRequest, config.container_depth, config.array_element_count, config.object_entry_count, config.object_entry_name_length, config.string_value_length)
            end
        end
    cjson = cjson.new()
  end

  local function error_handler(err)
        kong.log.set_serialize_value("request.JSON-Threat-Protection", err)
        local error_response = {
            message = "An unexpected error occurred in json_threat_protection",
            }
            return kong.response.exit(500, error_response, {
                ["Content-Type"] = "application/json"
            })
    end

  local status = xpcall(json_threat_protection, error_handler)

end

-- return our plugin object
return plugin
