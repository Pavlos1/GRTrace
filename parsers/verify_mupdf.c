#include <mupdf/fitz.h>
#include <stdio.h>

// Reference: http://mcs.une.edu.au/doc/mupdf/example.c
//
// Returns 0 for successful PDF parse, 1 if there was
// an error parsing the PDF (does not follow spec), and
// -1 if there was some other problem.
//
// (i.e. a return code of 1 is perfectly normal for the
// purposes of learing a grammar, but a -1 is not.)

int main(int argc, char **argv)
{
	char *input;
	int page_number, page_count;
	fz_context *ctx;
	fz_document *doc;
	fz_pixmap *pix;
    fz_matrix ctm;

	if (argc < 2)
	{
		fprintf(stderr, "FATAL: I need an input file.\n");
        exit(-1);
	}

	input = argv[1];

	/* Create a context to hold the exception stack and various caches. */
	ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
	if (!ctx)
	{
		fprintf(stderr, "FATAL: Cannot create mupdf context.\n");
		exit(-1);
	}

	/* Register the default file types to handle. */
	fz_try(ctx)
		fz_register_document_handlers(ctx);
	fz_catch(ctx)
	{
		fprintf(stderr, "FATAL: Cannot register document handlers: %s.\n", fz_caught_message(ctx));
		fz_drop_context(ctx);
		exit(-1);
	}

    FILE * fp = fopen(input, "r");
    if (!fp)
    {
        fprintf(stderr, "FATAL: File doesn't exist: %s.\n", input);
        fz_drop_context(ctx);
        exit(-1);
    }
    else
    {
        fclose(fp);
    }

	/* Open the document. */
	fz_try(ctx)
		doc = fz_open_document(ctx, input);
	fz_catch(ctx)
	{
		fprintf(stderr, "Parse error on opening document: %s.\n", fz_caught_message(ctx));
		fz_drop_context(ctx);
		exit(1);
	}

	/* Count the number of pages. */
	fz_try(ctx)
		page_count = fz_count_pages(ctx, doc);
	fz_catch(ctx)
	{
        fprintf(stderr, "Parse error during page count.\n");
		fz_drop_document(ctx, doc);
		fz_drop_context(ctx);
		exit(1);
	}

    /* Render pages to an RGB pixmap. */
    for (page_number = 0; page_number < page_count; page_number++)
    {
	    fz_try(ctx)
		    pix = fz_new_pixmap_from_page_number(ctx, doc, page_number, &ctm, fz_device_rgb(ctx), 255);
	    fz_catch(ctx)
	    {
		    fprintf(stderr, "Parse error rendering page %d: %s.\n", page_number, fz_caught_message(ctx));
		    fz_drop_document(ctx, doc);
		    fz_drop_context(ctx);
		    exit(1);
	    }
    }

	/* Clean up. */
	fz_drop_pixmap(ctx, pix);
	fz_drop_document(ctx, doc);
	fz_drop_context(ctx);

    return 0;
}
