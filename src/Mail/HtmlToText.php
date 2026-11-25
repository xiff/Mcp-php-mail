<?php

declare(strict_types=1);

namespace MailMcp\Mail;

/**
 * HTML -> texte brut. Rien n'est jamais chargé (pas de requête réseau) : scripts,
 * styles, images et liens disparaissent, seul le texte visible reste.
 */
final class HtmlToText
{
    public static function convert(string $html): string
    {
        $html = preg_replace('#<(script|style|head|title|noscript|template|svg|iframe|object)\b[^>]*>.*?</\1\s*>#is', ' ', $html) ?? '';
        $html = preg_replace('#<!--.*?-->#s', ' ', $html) ?? '';
        $html = preg_replace('#<(br|/p|/div|/tr|/li|/h[1-6]|/blockquote)\b[^>]*>#i', "\n", $html) ?? '';
        $text = html_entity_decode(strip_tags($html), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $text = preg_replace("/[ \t\x{00A0}]+/u", ' ', $text) ?? '';
        $text = preg_replace("/\n\s*\n\s*\n+/", "\n\n", $text) ?? '';

        return trim($text);
    }
}
