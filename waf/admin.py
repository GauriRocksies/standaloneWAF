"""
WAF Admin Configuration

Registers AttackLog, BlockedIP, RuleStats, and DetectorStats with the
Django admin. Follows the same style as blog/admin.py (list_display,
list_filter, search_fields, ordering).

Design note: AttackLog, RuleStats, and DetectorStats are all
system-generated (written by attack_logger.py / the models' own
record_*() methods) rather than hand-entered, so their admin pages
are read-only and disable "Add" — staff can inspect and delete, but
not fabricate attack history through the admin. BlockedIP stays fully
editable since manually unblocking (or extending a block on) an IP is
a legitimate day-to-day admin task.
"""

from django.contrib import admin
from django.utils.html import format_html

from waf.models import AttackLog, BlockedIP, RuleStats, DetectorStats


SEVERITY_COLORS = {
    'low': '#2ecc71',
    'medium': '#f1c40f',
    'high': '#e67e22',
    'critical': '#e74c3c',
}


@admin.register(AttackLog)
class AttackLogAdmin(admin.ModelAdmin):
    list_display = (
        'timestamp', 'ip_address', 'attack_type', 'colored_severity',
        'risk_score', 'method', 'url_preview', 'rule_triggered',
        'detector_name', 'blocked', 'response_code',
    )
    list_filter = ('attack_type', 'severity', 'blocked', 'method', 'detector_name')
    search_fields = ('ip_address', 'url', 'rule_triggered', 'detector_name', 'user_agent')
    ordering = ('-timestamp',)
    date_hierarchy = 'timestamp'
    list_per_page = 50
    readonly_fields = [f.name for f in AttackLog._meta.fields]

    @admin.display(description='Severity', ordering='severity')
    def colored_severity(self, obj):
        color = SEVERITY_COLORS.get(obj.severity, '#8ba3c0')
        return format_html(
            '<span style="color: {}; font-weight: 600;">{}</span>',
            color, obj.get_severity_display(),
        )

    @admin.display(description='URL')
    def url_preview(self, obj):
        return obj.url if len(obj.url) <= 60 else f'{obj.url[:60]}…'

    def has_add_permission(self, request):
        # Attack records are only ever created by attack_logger.log_attack()
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = (
        'ip_address', 'reason', 'blocked_at', 'expires_at',
        'is_active', 'attack_count',
    )
    list_filter = ('is_active',)
    search_fields = ('ip_address', 'reason')
    ordering = ('-blocked_at',)
    date_hierarchy = 'blocked_at'
    list_per_page = 50
    readonly_fields = ('blocked_at', 'attack_count')
    actions = ['unblock_selected', 'reactivate_selected']

    @admin.action(description='Deactivate selected blocks (unblock)')
    def unblock_selected(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f'{updated} IP(s) unblocked.')

    @admin.action(description='Reactivate selected blocks')
    def reactivate_selected(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} IP(s) reactivated.')


@admin.register(RuleStats)
class RuleStatsAdmin(admin.ModelAdmin):
    list_display = ('rule_name', 'trigger_count', 'last_triggered')
    search_fields = ('rule_name',)
    ordering = ('-trigger_count',)
    list_per_page = 50
    readonly_fields = ('rule_name', 'trigger_count', 'last_triggered')

    def has_add_permission(self, request):
        # Rows are created automatically by RuleStats.record_trigger()
        return False


@admin.register(DetectorStats)
class DetectorStatsAdmin(admin.ModelAdmin):
    list_display = (
        'detector_name', 'detection_count', 'false_positive_count', 'last_detection',
    )
    search_fields = ('detector_name',)
    ordering = ('-detection_count',)
    list_per_page = 50
    readonly_fields = ('detector_name', 'detection_count', 'false_positive_count', 'last_detection')

    def has_add_permission(self, request):
        # Rows are created automatically by DetectorStats.record_detection()
        return False