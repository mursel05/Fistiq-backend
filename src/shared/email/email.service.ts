import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { I18nContext, I18nService } from 'nestjs-i18n';
import nodemailer, { SentMessageInfo } from 'nodemailer';
import fs from 'fs';
import path from 'path';
import Handlebars from 'handlebars';

@Injectable()
export class EmailService {
  private transporter: nodemailer.Transporter;
  private readonly logger = new Logger(EmailService.name);
  private templates: Map<string, HandlebarsTemplateDelegate> = new Map();

  constructor(
    private readonly configService: ConfigService,
    private readonly i18nService: I18nService,
  ) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.get<string>('email.host'),
      port: Number(this.configService.get<number>('email.port')),
      secure: Boolean(this.configService.get('email.secure')),
      auth: {
        user: this.configService.get('email.user'),
        pass: this.configService.get('email.pass'),
      },
    });

    Handlebars.registerHelper(
      't',
      (key: string, options: Handlebars.HelperOptions) => {
        const lang = I18nContext.current()?.lang;
        return this.i18nService.t(key, {
          lang,
          args: (options?.hash as Record<string, unknown>) || {},
        });
      },
    );

    Handlebars.registerHelper('translate', (obj: Record<string, string>) => {
      const lang = I18nContext.current()?.lang || 'en';
      return obj?.[lang] || obj?.en || '';
    });
  }

  private getTemplate(templateName: string): HandlebarsTemplateDelegate {
    if (!this.templates.has(templateName)) {
      const templatePath = path.join(
        __dirname,
        'templates',
        `${templateName}.hbs`,
      );
      const templateContent = fs.readFileSync(templatePath, 'utf-8');
      this.templates.set(templateName, Handlebars.compile(templateContent));
    }
    return this.templates.get(templateName)!;
  }

  private async sendEmail(
    to: string,
    subject: string,
    html: string,
  ): Promise<SentMessageInfo> {
    try {
      const info: unknown = await this.transporter.sendMail({
        from: `"Fistiq" <${this.configService.get('email.user')}>`,
        to,
        subject,
        html,
      });
      this.logger.log(`Email sent to ${to} with subject "${subject}"`);
      return info;
    } catch (error) {
      this.logger.error(
        `Failed to send email to ${to} with subject "${subject}": ${error}`,
      );
    }
  }

  async sendResetCode(email: string, code: number): Promise<void> {
    try {
      const template = this.getTemplate('password-reset');
      const subject = this.i18nService.t('email.passwordReset.subject');
      const html = template({
        code,
        lang: I18nContext.current()?.lang,
        currentYear: new Date().getFullYear(),
        t: (key: string) => this.i18nService.t(key),
      });
      await this.sendEmail(email, subject, html);
      this.logger.log(`Password reset code sent to ${email}`);
    } catch (error) {
      this.logger.error(
        `Failed to send password reset code to ${email}: ${error}`,
      );
    }
  }
}
