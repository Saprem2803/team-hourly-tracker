import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL     = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SERVICE_ROLE_KEY")!;

const adminClient = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
});

const corsHeaders = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
};

serve(async (req) => {
    if (req.method === "OPTIONS") {
        return new Response("ok", { headers: corsHeaders });
    }

    try {
        // 1. Verify caller is authenticated + management
        const authHeader = req.headers.get("Authorization");
        if (!authHeader) throw new Error("Missing Authorization header");

        const callerClient = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
            global: { headers: { Authorization: authHeader } }
        });

        const { data: { user }, error: authError } = await callerClient.auth.getUser();
        if (authError || !user) throw new Error("Invalid or expired session");

        const { data: callerAccess, error: accessError } = await adminClient
            .from("user_project_access")
            .select("role, active")
            .eq("user_id", user.id)
            .eq("role", "management")
            .eq("active", true)
            .maybeSingle();

        if (accessError || !callerAccess) {
            throw new Error("Only management users can perform this action");
        }

        // 2. Route the action
        const body = await req.json();
        const { action } = body;

        // -------- CREATE USER --------
        if (action === "create") {
            const { email, password, full_name, role, project_id } = body;

            if (!email || !password || !role) {
                throw new Error("Missing required fields: email, password, role");
            }
            if (!["management", "team_lead", "tracker"].includes(role)) {
                throw new Error("Invalid role. Allowed: management, team_lead, tracker");
            }

            const { data: newUser, error: createError } = await adminClient.auth.admin.createUser({
                email,
                password,
                email_confirm: true,
                user_metadata: { full_name: full_name || "" }
            });
            if (createError) throw createError;

            const userId = newUser.user.id;

            const { error: upaError } = await adminClient
                .from("user_project_access")
                .insert({
                    user_id:        userId,
                    email:          email,
                    full_name:      full_name || "",
                    role:           role,
                    project_id:     project_id || null,
                    team_lead_name: role === "team_lead" ? (full_name || "") : null,
                    active:         true
                });
            if (upaError) {
                await adminClient.auth.admin.deleteUser(userId);
                throw upaError;
            }

            if (role === "team_lead") {
                await adminClient.from("team_leads").insert({
                    full_name:  full_name || "",
                    email:      email,
                    user_id:    userId,
                    project_id: project_id || null,
                    active:     true
                });
            }

            if (role === "tracker") {
                await adminClient.from("trackers").insert({
                    full_name:  full_name || "",
                    email:      email,
                    user_id:    userId,
                    project_id: project_id || null,
                    active:     true
                });
            }

            return new Response(JSON.stringify({
                success: true,
                user_id: userId,
                message: `User ${email} created successfully`
            }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // -------- RESET PASSWORD --------
        if (action === "reset_password") {
            const { user_id, new_password } = body;
            if (!user_id || !new_password) throw new Error("Missing user_id or new_password");

            const { error } = await adminClient.auth.admin.updateUserById(user_id, {
                password: new_password
            });
            if (error) throw error;

            return new Response(JSON.stringify({ success: true, message: "Password reset" }),
                { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // -------- UPDATE EMAIL --------
        if (action === "update_email") {
            const { user_id, new_email } = body;
            if (!user_id || !new_email) throw new Error("Missing user_id or new_email");

            const { error } = await adminClient.auth.admin.updateUserById(user_id, {
                email: new_email,
                email_confirm: true
            });
            if (error) throw error;

            await adminClient
                .from("user_project_access")
                .update({ email: new_email })
                .eq("user_id", user_id);

            return new Response(JSON.stringify({ success: true, message: "Email updated" }),
                { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // -------- DEACTIVATE USER --------
        if (action === "deactivate") {
            const { user_id, role } = body;
            if (!user_id) throw new Error("Missing user_id");

            await adminClient
                .from("user_project_access")
                .update({ active: false })
                .eq("user_id", user_id);

            await adminClient.auth.admin.updateUserById(user_id, {
                ban_duration: "876000h"
            });

            if (role === "team_lead") {
                await adminClient
                    .from("team_leads")
                    .update({ active: false, project_id: null })
                    .eq("user_id", user_id);
            } else if (role === "tracker") {
                await adminClient
                    .from("trackers")
                    .update({ active: false, project_id: null })
                    .eq("user_id", user_id);
            }

            return new Response(JSON.stringify({
                success: true,
                message: "User deactivated. Historical data preserved."
            }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // -------- REACTIVATE USER --------
        if (action === "reactivate") {
            const { user_id } = body;
            if (!user_id) throw new Error("Missing user_id");

            await adminClient
                .from("user_project_access")
                .update({ active: true })
                .eq("user_id", user_id);

            await adminClient.auth.admin.updateUserById(user_id, {
                ban_duration: "none"
            });

            return new Response(JSON.stringify({ success: true, message: "User reactivated" }),
                { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // -------- DELETE USER --------
        if (action === "delete") {
            const { user_id } = body;
            if (!user_id) throw new Error("Missing user_id");

            await adminClient.from("team_leads").delete().eq("user_id", user_id);
            await adminClient.from("trackers").delete().eq("user_id", user_id);
            await adminClient.from("user_project_access").delete().eq("user_id", user_id);

            const { error } = await adminClient.auth.admin.deleteUser(user_id);
            if (error) throw error;

            return new Response(JSON.stringify({ success: true, message: "User deleted permanently" }),
                { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        throw new Error(`Unknown action: ${action}`);

    } catch (error) {
        console.error("Edge Function error:", error);
        return new Response(JSON.stringify({
            error: error.message || "Unknown error"
        }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
    }
});
